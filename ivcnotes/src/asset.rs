use crate::{Address, AssetHash, FWrap};
use ark_ff::PrimeField;
use digest::Digest;

#[derive(Debug, Clone, Copy)]
// Represents an asset with an issuer and terms
pub struct Asset<F: PrimeField> {
    // The address of the issuer of the asset
    pub(crate) issuer: Address<F>,
    // The terms associated with the asset
    pub(crate) terms: Terms,
}

impl<F: PrimeField> Asset<F> {
    // Creates a new Asset with the given issuer and terms
    pub fn new(issuer: &Address<F>, terms: &Terms) -> Self {
        Asset {
            issuer: *issuer,
            terms: *terms,
        }
    }

    // Computes a hash for the asset
    pub(crate) fn hash(&self) -> AssetHash<F> {
        let bytes = sha2::Sha512::new()
            .chain_update(self.terms.to_bytes())
            .chain_update(self.issuer.to_bytes())
            .finalize();
        AssetHash::reduce_bytes(bytes.as_ref())
    }
}

#[derive(Debug, Clone, Copy)]
// Represents the terms of an asset
pub enum Terms {
    // IOU terms with maturity and unit values
    IOU { maturity: u64, unit: u64 },
}

impl Terms {
    // Creates a new IOU term with the given maturity and unit values
    pub fn iou(maturity: u64, unit: u64) -> Self {
        Terms::IOU { maturity, unit }
    }

    // Converts the terms to a byte vector
    fn to_bytes(self) -> Vec<u8> {
        match self {
            Terms::IOU { maturity, unit } => {
                let mut bytes = vec![];
                bytes.extend_from_slice(&maturity.to_le_bytes());
                bytes.extend_from_slice(&unit.to_le_bytes());
                bytes
            }
        }
    }
}
