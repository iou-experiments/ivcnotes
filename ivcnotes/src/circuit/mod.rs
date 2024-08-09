use std::io::Read;

use crate::poseidon::PoseidonConfigs;
use ark_crypto_primitives::snark::SNARK;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Result as CSResult};
use ark_serialize::CanonicalDeserialize;
use cs::synth;
use inputs::{AuxInputs, PublicInput};
use rand::{CryptoRng, RngCore};

pub mod cs;
pub mod inputs;

pub trait IVC: Clone {
    // proof system config
    type Snark: SNARK<Self::Field>;
    // application field
    type Field: PrimeField + Absorb;
    // inner curve - (baby)jubjub config
    type TE: TECurveConfig<BaseField = Self::Field> + Clone;

    fn read_proving_key<R: Read>(
        reader: R,
    ) -> Result<<Self::Snark as SNARK<Self::Field>>::ProvingKey, crate::Error> {
        <Self::Snark as SNARK<Self::Field>>::ProvingKey::deserialize_compressed(reader)
            .map_err(|e| crate::Error::Data(format!("proving key deserialization failed: {}", e)))
    }

    fn read_verifying_key<R: Read>(
        reader: R,
    ) -> Result<<Self::Snark as SNARK<Self::Field>>::VerifyingKey, crate::Error> {
        <Self::Snark as SNARK<Self::Field>>::VerifyingKey::deserialize_compressed(reader)
            .map_err(|e| crate::Error::Data(format!("verifying key deserialization failed: {}", e)))
    }
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
            .map_err(|e| crate::Error::Data(format!("proof generation failed: {}", e)))
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
            .map_err(|e| crate::Error::Data(format!("verification failed: {}", e)))
    }
}

pub mod concrete {

    use super::{Circuit, IVC};
    use crate::poseidon::PoseidonConfigs;
    use ark_bn254::{Bn254, Fr};
    use ark_crypto_primitives::{
        snark::{CircuitSpecificSetupSNARK, SNARK},
        sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig},
    };
    use ark_ed_on_bn254::EdwardsConfig;
    use ark_ff::PrimeField;
    use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
    use lazy_static::lazy_static;
    use rand_core::OsRng;

    lazy_static! {
        pub static ref POSEIDON_CFG: PoseidonConfigs::<Fr> = poseidon_cfg();
    }

    type JubJub = EdwardsConfig;

    #[derive(Clone)]
    pub struct Concrete;

    pub type ConcreteF = <Concrete as IVC>::Field;
    pub type ConcreteVK = <<Concrete as IVC>::Snark as SNARK<ConcreteF>>::VerifyingKey;
    pub type ConcretePK = <<Concrete as IVC>::Snark as SNARK<ConcreteF>>::ProvingKey;
    pub type ConcreteTE = <Concrete as IVC>::TE;

    impl IVC for Concrete {
        type Snark = Groth16<Bn254>;
        type Field = Fr;
        type TE = JubJub;
    }

    pub fn poseidon_cfg() -> PoseidonConfigs<Fr> {
        let rate = 2;
        let full_rounds = 8;
        let partial_rounds = 55;
        let prime_bits = Fr::MODULUS_BIT_SIZE as u64;
        let (constants, mds) =
            find_poseidon_ark_and_mds::<Fr>(prime_bits, 2, full_rounds, partial_rounds, 0);
        let poseidon_cfg = PoseidonConfig::<Fr>::new(
            full_rounds as usize,
            partial_rounds as usize,
            5,
            mds.clone(),
            constants.clone(),
            rate,
            1,
        );

        PoseidonConfigs::<Fr> {
            id: poseidon_cfg.clone(),
            note: poseidon_cfg.clone(),
            blind: poseidon_cfg.clone(),
            state: poseidon_cfg.clone(),
            nullifier: poseidon_cfg.clone(),
            tx: poseidon_cfg.clone(),
            eddsa: poseidon_cfg.clone(),
        }
    }

    pub fn circuit_setup() -> (ProvingKey<Bn254>, VerifyingKey<Bn254>) {
        let circuit: Circuit<Concrete> = Circuit::empty(&POSEIDON_CFG);
        Groth16::<Bn254>::setup(circuit, &mut OsRng).unwrap()
    }

    #[test]
    fn test_circuit_setup() {
        circuit_setup();
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::fmt::Debug;

    use ark_bn254::Fr;
    use ark_crypto_primitives::snark::SNARK;
    use ark_ed_on_bn254::EdwardsConfig;
    use ark_ff::PrimeField;
    use ark_relations::r1cs::ConstraintSynthesizer;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use rand::{CryptoRng, RngCore};

    use crate::wallet::Contact;

    use super::IVC;

    #[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
    pub(crate) struct MockArkElement {}

    pub(crate) struct MockSNARK {}

    impl<F: PrimeField> SNARK<F> for MockSNARK {
        type ProvingKey = MockArkElement;
        type VerifyingKey = MockArkElement;
        type Proof = MockArkElement;
        type ProcessedVerifyingKey = MockArkElement;
        type Error = crate::Error;

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

    impl Debug for Contact<ConcreteIVC> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Contact")
                .field("address", &self.address)
                .field("username", &self.username)
                .finish()
        }
    }

    #[derive(Clone)]
    pub(crate) struct ConcreteIVC {}

    impl IVC for ConcreteIVC {
        type Snark = MockSNARK;
        type Field = Fr;
        type TE = EdwardsConfig;
    }
}
