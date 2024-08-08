use crate::{Address, AssetHash, FWrap};
use ark_ff::PrimeField;
use digest::Digest;
use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u64)]
pub enum Unit {
    USD = 0,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Asset<F: PrimeField> {
    #[serde(with = "crate::ark_serde")]
    pub(crate) issuer: Address<F>,
    pub(crate) terms: Terms,
}

impl<F: PrimeField> Asset<F> {
    pub fn new(issuer: &Address<F>, terms: &Terms) -> Self {
        Asset {
            issuer: *issuer,
            terms: *terms,
        }
    }

    pub(crate) fn hash(&self) -> AssetHash<F> {
        let bytes = sha2::Sha512::new()
            .chain_update(self.terms.to_bytes())
            .chain_update(self.issuer.to_bytes())
            .finalize();
        AssetHash::reduce_bytes(bytes.as_ref())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Terms {
    IOU { maturity: u64, unit: Unit },
}

impl Terms {
    pub fn iou(maturity: u64, unit: Unit) -> Self {
        Terms::IOU { maturity, unit }
    }

    fn to_bytes(self) -> Vec<u8> {
        match self {
            Terms::IOU { maturity, unit } => {
                let mut bytes = vec![];
                bytes.extend_from_slice(&maturity.to_le_bytes());
                bytes.extend_from_slice(&(unit as u64).to_le_bytes());
                bytes
            }
        }
    }
}
