use crate::{
    cipher::{CipherText, EncryptedData},
    circuit::IVC,
    poseidon::PoseidonConfigs,
    Address, Error, FWrap, NullifierKey, SigHash,
};
use ark_crypto_primitives::sponge::{poseidon::PoseidonConfig, Absorb};
use arkeddsa::{signature::Signature, PublicKey, SigningKey};
use rand_core::CryptoRngCore;
type PreHash = sha2::Sha512;

#[derive(Debug)]
// Signer has the signer key and eddsa poseidon config
pub struct Signer<E: IVC> {
    signing_key: SigningKey<E::TE>,
    poseidon: PoseidonConfig<E::Field>,
}

impl<E: IVC> Signer<E> {
    pub(crate) fn generate(
        poseidon: &PoseidonConfig<E::Field>,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let signing_key = SigningKey::generate::<PreHash>(rng).unwrap();
        Self {
            signing_key,
            poseidon: poseidon.clone(),
        }
    }

    pub(crate) fn sign<A: Absorb>(&self, msg: &[A]) -> Signature<E::TE> {
        self.signing_key.sign::<PreHash, A>(&self.poseidon, msg)
    }

    pub(crate) fn public_key(&self) -> &PublicKey<E::TE> {
        self.signing_key.public_key()
    }
}

// `Id` holds user secrets and public address
pub struct Auth<E: IVC> {
    nullifier_key: NullifierKey<E::Field>,
    signer: Signer<E>,
    address: Address<E::Field>,
}

impl<E: IVC> Auth<E> {
    pub fn generate(
        h: &PoseidonConfigs<E::Field>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, Error> {
        let signer = Signer::generate(&h.eddsa, rng);
        let nullifier_key = NullifierKey::rand(rng);
        let address = h.id_commitment(&nullifier_key, signer.public_key());
        Ok(Self {
            nullifier_key,
            signer,
            address,
        })
    }

    pub(crate) fn encrypt<T: CipherText>(
        &self,
        receiver: &PublicKey<E::TE>,
        data: &T,
    ) -> EncryptedData {
        let shared = self.shared_key(receiver);
        T::encrypt(&shared, data)
    }

    pub(crate) fn decrypt<T: CipherText>(
        &self,
        sender: &PublicKey<E::TE>,
        data: &EncryptedData,
    ) -> Result<T, Error> {
        let shared = self.shared_key(sender);
        T::decrypt(&shared, data)
    }

    pub(crate) fn address(&self) -> &Address<E::Field> {
        &self.address
    }

    pub(crate) fn nullifier_key(&self) -> &NullifierKey<E::Field> {
        &self.nullifier_key
    }

    pub(crate) fn public_key(&self) -> &PublicKey<E::TE> {
        self.signer.public_key()
    }

    pub(crate) fn shared_key(&self, receiver: &PublicKey<E::TE>) -> [u8; 32] {
        // TODO use different key for shared key
        self.signer.signing_key.shared_key::<sha2::Sha512>(receiver)
    }

    pub(crate) fn sign_tx(&self, msg: &SigHash<E::Field>) -> Signature<E::TE> {
        self.signer.sign(&[msg.inner()])
    }

    pub(crate) fn sign<A: Absorb>(&self, msg: &[A]) -> Signature<E::TE> {
        self.signer.sign(msg)
    }
}
