use crate::crypto::hasher::NtoOneHasher;
use crate::{crypto::circuit::SNARK, FWrap};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use arkeddsa::{signature::Signature, PublicKey, SigningKey};
use rand_core::CryptoRngCore;

crate::field_wrap!(SigHash);
crate::field_wrap!(Address);
crate::field_wrap!(NullifierKey);

// We will also use id commitment as user address
// `id_comm = hash(nullifier_key || pub_key.x || pub_key.y)`
pub fn id_commitment<E: SNARK>(
    hasher: &E::Hasher,
    nullifier_key: &NullifierKey<E::AppField>,
    public_key: &PublicKey<E::Ed>,
) -> Address<E::AppField> {
    let (x, y) = public_key.xy();
    hasher.compress(&[nullifier_key.inner(), *x, *y]).into()
}

#[derive(Debug)]
// Signer has the signer key and eddsa poseidon config
pub struct Signer<E: SNARK> {
    signing_key: SigningKey<E::Ed>,
    poseidon: PoseidonConfig<E::AppField>,
}

impl<E: SNARK> Signer<E> {
    pub(crate) fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
        let poseidon = E::Hasher::eddsa_config();
        let signing_key = SigningKey::generate::<sha2::Sha512>(rng).unwrap();
        Self {
            signing_key,
            poseidon,
        }
    }

    pub(crate) fn sign(&self, msg: &E::AppField) -> Signature<E::Ed> {
        self.signing_key
            .sign::<sha2::Sha512, _>(&self.poseidon, &[*msg])
    }

    pub(crate) fn public_key(&self) -> &PublicKey<E::Ed> {
        self.signing_key.public_key()
    }
}

#[derive(Debug)]
// `Id` holds user secrets and public address
pub struct Auth<E: SNARK> {
    nullifier_key: NullifierKey<E::AppField>,
    signer: Signer<E>,
    address: Address<E::AppField>,
}

impl<E: SNARK> Auth<E> {
    pub fn generate(rng: &mut impl CryptoRngCore, hasher: &E::Hasher) -> Self {
        let signer = Signer::generate(rng);
        let nullifier_key = NullifierKey::rand(rng);
        let address = id_commitment::<E>(hasher, &nullifier_key, signer.signing_key.public_key());
        Self {
            nullifier_key,
            signer,
            address,
        }
    }

    pub(crate) fn address(&self) -> &Address<E::AppField> {
        &self.address
    }

    pub(crate) fn nullifier_key(&self) -> &NullifierKey<E::AppField> {
        &self.nullifier_key
    }

    pub(crate) fn public_key(&self) -> &PublicKey<E::Ed> {
        self.signer.public_key()
    }

    pub(crate) fn sign(&self, msg: &SigHash<E::AppField>) -> Signature<E::Ed> {
        self.signer.sign(&msg.inner())
    }
}
