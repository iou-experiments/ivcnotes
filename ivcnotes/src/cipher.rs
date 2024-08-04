use crate::Error;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

// some taken from https://github.com/Mach-34/Grapevine

struct AesKey {
    key: [u8; 16],
    iv: [u8; 16],
}

fn gen_aes_key(shared_key: &[u8; 32]) -> AesKey {
    let shared = Sha256::digest(shared_key);
    let key: [u8; 16] = shared[0..16].try_into().unwrap();
    let iv: [u8; 16] = shared[16..32].try_into().unwrap();
    AesKey { key, iv }
}

pub(crate) fn encrypt(shared_key: &[u8; 32], msg: &[u8]) -> Vec<u8> {
    let aes_key = gen_aes_key(shared_key);
    let c = Aes128CbcEnc::new_from_slices(&aes_key.key, &aes_key.iv).unwrap();
    c.encrypt_padded_vec_mut::<Pkcs7>(msg)
}

pub(crate) fn decrypt(shared_key: &[u8; 32], msg: &[u8]) -> Vec<u8> {
    let aes_key = gen_aes_key(shared_key);
    let c = Aes128CbcDec::new_from_slices(&aes_key.key, &aes_key.iv).unwrap();
    c.decrypt_padded_vec_mut::<Pkcs7>(msg).unwrap()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedData {
    pub(crate) data: Vec<u8>,
}

impl From<Vec<u8>> for EncryptedData {
    fn from(data: Vec<u8>) -> Self {
        EncryptedData { data }
    }
}

impl AsRef<[u8]> for EncryptedData {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

pub trait CipherText: serde::Serialize + for<'de> serde::Deserialize<'de> {
    fn encrypt(shared_key: &[u8; 32], obj: &Self) -> EncryptedData {
        let data = bincode::serialize(obj).unwrap();
        let data = encrypt(shared_key, &data);
        EncryptedData { data }
    }

    fn decrypt(shared_key: &[u8; 32], data: &EncryptedData) -> Result<Self, Error> {
        let data = decrypt(shared_key, data.as_ref());
        bincode::deserialize(&data).map_err(|e| Error::Data(format!("decryption failed: {}", e)))
    }
}

impl<T: serde::Serialize + for<'de> serde::Deserialize<'de>> CipherText for T {}
