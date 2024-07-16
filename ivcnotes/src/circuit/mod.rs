use crate::poseidon::PoseidonConfigs;
use ark_crypto_primitives::snark::SNARK;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::twisted_edwards::{Affine, TECurveConfig};
use ark_ec::{AffineRepr, CurveConfig};
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::nonnative::NonNativeFieldVar;
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::ToBitsGadget;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, Namespace, Result as CSResult,
};
use cs::synth;
use inputs::{AuxInputs, PublicInput};
use rand::{CryptoRng, RngCore};

pub mod cs;
pub mod inputs;

fn verify_signature<F: PrimeField, TE: TECurveConfig<BaseField = F>>(
    cs: impl Into<Namespace<F>>,
    poseidon: &PoseidonConfig<F>,
    pubkey: &AffineVar<TE, FpVar<F>>,
    sig_r: &AffineVar<TE, FpVar<F>>,
    sig_s: &NonNativeFieldVar<<TE as CurveConfig>::ScalarField, F>,
    msg: &FpVar<F>,
) -> CSResult<()> {
    let cs = cs.into().cs();

    let b = AffineVar::new_constant(cs.clone(), Affine::<_>::generator())?;
    let mut poseidon = PoseidonSpongeVar::new(cs.clone(), poseidon);

    // TODO: move to configs
    poseidon.absorb(&sig_r)?;
    poseidon.absorb(&pubkey)?;
    poseidon.absorb(msg)?;

    let (_, k_bits) =
        poseidon.squeeze_nonnative_field_elements::<<TE as CurveConfig>::ScalarField>(1)?;

    let kx_b0 = pubkey.scalar_mul_le(k_bits.first().unwrap().iter())?;
    let sig_s_bits = sig_s.to_bits_le()?;
    let s_b = b.scalar_mul_le(sig_s_bits.iter())?;

    sig_r.enforce_equal(&(s_b - kx_b0))
}

pub trait IVC: Clone {
    // proof system config
    type Snark: SNARK<Self::Field>;
    // application field
    type Field: PrimeField + Absorb;
    // inner curve - (baby)jubjub config
    type TE: TECurveConfig<BaseField = Self::Field> + Clone;
}

pub struct Circuit<'a, E: IVC> {
    pub(crate) h: &'a PoseidonConfigs<E::Field>,
    pub(crate) public: Option<PublicInput<E::Field>>,
    pub(crate) aux: Option<AuxInputs<E>>,
}

impl<'a, E: IVC> Circuit<'a, E> {
    pub fn new(
        h: &'a PoseidonConfigs<E::Field>,
        public: PublicInput<E::Field>,
        aux: AuxInputs<E>,
    ) -> Self {
        Self {
            h,
            public: Some(public),
            aux: Some(aux),
        }
    }

    pub fn empty(h: &'a PoseidonConfigs<E::Field>) -> Self {
        Self {
            h,
            public: None,
            aux: None,
        }
    }
}

impl<'a, E: IVC> ConstraintSynthesizer<E::Field> for Circuit<'a, E> {
    fn generate_constraints(self, cs: ConstraintSystemRef<E::Field>) -> CSResult<()> {
        synth(cs, self)
    }
}

pub struct Prover<E: IVC> {
    pub(crate) pk: <<E as IVC>::Snark as SNARK<E::Field>>::ProvingKey,
}

pub struct Verifier<E: IVC> {
    pub(crate) vk: <<E as IVC>::Snark as SNARK<E::Field>>::VerifyingKey,
}

impl<E: IVC> Prover<E> {
    pub fn create_proof<R: RngCore + CryptoRng>(
        &self,
        h: &PoseidonConfigs<E::Field>,
        public: PublicInput<E::Field>,
        aux: AuxInputs<E>,
        rng: &mut R,
    ) -> Result<<<E as IVC>::Snark as SNARK<E::Field>>::Proof, crate::Error> {
        let circuit = Circuit::new(h, public, aux);
        <E as IVC>::Snark::prove(&self.pk, circuit, rng)
            .map_err(|_err| crate::Error::With("proof generation failed"))
    }
}

impl<E: IVC> Verifier<E> {
    pub fn verify_proof(
        &self,
        proof: &<<E as IVC>::Snark as SNARK<E::Field>>::Proof,
        pi: &PublicInput<E::Field>,
    ) -> Result<bool, crate::Error> {
        let pi = pi.to_verifier();
        E::Snark::verify(&self.vk, &pi, proof)
            .map_err(|_err| crate::Error::With("verification failed"))
    }
}
