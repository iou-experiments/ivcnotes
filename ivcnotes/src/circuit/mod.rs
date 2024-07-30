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
    pub fn new(pk: <<E as IVC>::Snark as SNARK<E::Field>>::ProvingKey) -> Self {
        Self { pk }
    }

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
    pub fn new(vk: <<E as IVC>::Snark as SNARK<E::Field>>::VerifyingKey) -> Self {
        Self { vk }
    }

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

#[cfg(test)]
pub(crate) mod test {
    use std::{fmt::Debug, marker::PhantomData};

    use ark_bn254::Fr;
    use ark_crypto_primitives::{snark::SNARK, sponge::Absorb};
    use ark_ec::twisted_edwards::TECurveConfig;
    use ark_ed_on_bn254::EdwardsConfig;
    use ark_ff::PrimeField;
    use ark_relations::r1cs::ConstraintSynthesizer;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use rand::{CryptoRng, RngCore};

    use crate::{wallet::Contact, Error};

    use super::IVC;

    #[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
    pub(crate) struct MockArkElement {}

    pub(crate) struct MockSNARK {}

    impl<F: PrimeField> SNARK<F> for MockSNARK {
        type ProvingKey = MockArkElement;
        type VerifyingKey = MockArkElement;
        type Proof = MockArkElement;
        type ProcessedVerifyingKey = MockArkElement;
        type Error = Error;

        fn circuit_specific_setup<C: ConstraintSynthesizer<F>, R: RngCore + CryptoRng>(
            _circuit: C,
            _rng: &mut R,
        ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error> {
            Ok((MockArkElement {}, MockArkElement {}))
        }

        fn prove<C: ConstraintSynthesizer<F>, R: RngCore + CryptoRng>(
            _circuit_pk: &Self::ProvingKey,
            _circuit: C,
            _rng: &mut R,
        ) -> Result<Self::Proof, Self::Error> {
            Ok(MockArkElement {})
        }

        fn process_vk(
            _circuit_vk: &Self::VerifyingKey,
        ) -> Result<Self::ProcessedVerifyingKey, Self::Error> {
            Ok(MockArkElement {})
        }

        fn verify_with_processed_vk(
            _circuit_pvk: &Self::ProcessedVerifyingKey,
            _public_input: &[F],
            _proof: &Self::Proof,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    #[derive(Clone)]
    struct MockIVC<TE: TECurveConfig>
    where
        TE::BaseField: PrimeField,
    {
        _marker: PhantomData<TE>,
    }

    impl<TE: TECurveConfig + Clone> IVC for MockIVC<TE>
    where
        TE::BaseField: PrimeField + Absorb,
    {
        type Snark = MockSNARK;
        type Field = TE::BaseField;
        type TE = TE;
    }

    #[derive(Clone)]
    pub(crate) struct ConcreteIVC {}

    impl Debug for ConcreteIVC {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("ConcreteIVC")
        }
    }

    impl Debug for Contact<ConcreteIVC> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Contact")
                .field("address", &self.address)
                .field("username", &self.username)
                .finish()
        }
    }

    impl IVC for ConcreteIVC {
        type Snark = MockSNARK;
        type Field = Fr;
        type TE = EdwardsConfig;
    }
}
