use crate::{
    cipher::{CipherText, EncryptedData},
    circuit::IVC,
    poseidon::PoseidonConfigs,
    Address, Error, FWrap, NullifierKey, SigHash,
};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::PrimeField;
use arkeddsa::{signature::Signature, PublicKey, SigningKey};
use rand_core::CryptoRngCore;
use sha2::Digest;

pub struct Auth<E: IVC> {
    h: PoseidonConfig<E::Field>,
    secret: [u8; 32],
    address: Address<E::Field>,
    public_key: PublicKey<E::TE>,
}

fn nullifier_key<F: PrimeField>(secret: &[u8; 32]) -> NullifierKey<F> {
    let mut d = sha2::Sha512::new();
    d.update(b"nullifier");
    d.update(secret);
    let nullifier = d.finalize();
    NullifierKey::from_bignumber(&nullifier[..])
}

fn signer<E: IVC>(secret: &[u8; 32]) -> SigningKey<E::TE> {
    let mut d = sha2::Sha512::new();
    d.update(b"eddsa");
    d.update(secret);
    let secret = d.finalize().to_vec();
    SigningKey::from_bytes::<sha2::Sha512>(&secret[00..32].try_into().unwrap()).unwrap()
}

impl<E: IVC> Auth<E> {
    pub fn generate(
        h: &PoseidonConfigs<E::Field>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, Error> {
        let mut secret = [0; 32];
        rng.fill_bytes(&mut secret);
        Self::new(h, secret)
    }

    pub fn new(h: &PoseidonConfigs<E::Field>, secret: [u8; 32]) -> Result<Self, Error> {
        let signer: SigningKey<E::TE> = signer::<E>(&secret);
        let nullifier_key = nullifier_key(&secret);
        let address = h.id_commitment(&nullifier_key, signer.public_key());
        let public_key = signer.public_key().clone();
        Ok(Self {
            secret,
            address,
            public_key,
            h: h.eddsa.clone(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.secret.to_vec()
    }

    pub fn address(&self) -> &Address<E::Field> {
        &self.address
    }

    pub(crate) fn nullifier_key(&self) -> NullifierKey<E::Field> {
        nullifier_key(&self.secret)
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

    pub(crate) fn public_key(&self) -> &PublicKey<E::TE> {
        &self.public_key
    }

    pub(crate) fn signer(&self) -> SigningKey<E::TE> {
        signer::<E>(&self.secret)
    }

    pub(crate) fn shared_key(&self, receiver: &PublicKey<E::TE>) -> [u8; 32] {
        self.signer().shared_key::<sha2::Sha512>(receiver)
    }

    pub(crate) fn sign_tx(&self, msg: &SigHash<E::Field>) -> Signature<E::TE> {
        self.signer()
            .sign::<sha2::Sha512, _>(&self.h, &[msg.inner()])
    }
}
