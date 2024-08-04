use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use serde::Deserialize;
use serde::Serialize;
use std::borrow::Borrow;

pub mod asset;
pub mod cipher;
pub mod circuit;
pub mod id;
pub mod note;
pub mod poseidon;
pub mod pretty;
pub mod service;
pub mod tx;
pub mod wallet;
pub use arkeddsa::PublicKey;

crate::field_wrap!(SigHash);
crate::field_wrap!(Address);
crate::field_wrap!(NullifierKey);
crate::field_wrap!(Nullifier);
crate::field_wrap!(StateHash);
crate::field_wrap!(AssetHash);
crate::field_wrap!(Blind);
crate::field_wrap!(NoteHash);
crate::field_wrap!(BlindNoteHash);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Custom(String),
    Data(String),
    External(String),
    Verify(String),
    Service(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let string = match self {
            Self::Custom(s)
            | Self::Data(s)
            | Self::External(s)
            | Self::Verify(s)
            | Self::Service(s) => s.clone(),
        };
        write!(f, "{}", string)
    }
}

impl ark_std::error::Error for Error {}

pub trait FWrap<F: ark_ff::PrimeField>: From<F> + AsRef<F> + Clone + Copy {
    fn inner(&self) -> F;

    fn rand(rng: &mut impl rand::RngCore) -> Self {
        F::rand(rng).into()
    }

    fn hash<D: digest::Digest>(&self) -> Vec<u8> {
        use ark_serialize::CanonicalSerializeHashExt;
        self.inner().hash_uncompressed::<D>().to_vec()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.inner().serialize_compressed(&mut bytes).unwrap();
        bytes
    }

    fn to_string(&self) -> String {
        self.inner().to_string()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn ark_std::error::Error>> {
        let deserialized = F::deserialize_compressed(bytes)?;
        Ok(deserialized.into())
    }

    fn from_bignumber(bytes: &[u8]) -> Self {
        F::from_le_bytes_mod_order(bytes).into()
    }

    fn reduce_bytes(bytes: &[u8]) -> Self {
        F::from_le_bytes_mod_order(bytes).into()
    }

    fn serialize<S>(x: &Self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        x.to_bytes().serialize(s)
    }

    fn deserialize<'de, D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(d)?;
        Ok(Self::from_bytes(&bytes).unwrap())
    }

    fn short_hex(&self) -> String {
        let bytes = self.to_bytes();
        let mut s = "0x".to_string();
        for b in bytes.iter().rev().take(4) {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}

pub use ark_std::io::{Read, Write};

#[macro_export]
macro_rules! field_wrap {
    ($name:ident) => {
        #[derive(
            Clone,
            Copy,
            Default,
            Eq,
            PartialEq,
            Hash,
            Ord,
            PartialOrd,
            CanonicalSerialize,
            CanonicalDeserialize,
        )]
        pub struct $name<F: ark_ff::PrimeField>(F);

        impl<F: ark_ff::PrimeField> core::fmt::Debug for $name<F> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}", self.0.to_string())
            }
        }

        impl<F: ark_ff::PrimeField> From<F> for $name<F> {
            fn from(value: F) -> Self {
                Self(value)
            }
        }

        impl<F: ark_ff::PrimeField> From<&F> for $name<F> {
            fn from(value: &F) -> Self {
                Self(*value)
            }
        }

        impl<F: ark_ff::PrimeField> AsRef<F> for $name<F> {
            fn as_ref(&self) -> &F {
                &self.0
            }
        }

        impl<F: ark_ff::PrimeField> FWrap<F> for $name<F> {
            fn inner(&self) -> F {
                self.0
            }
        }

        impl<V: ark_ff::PrimeField> Borrow<V> for $name<V> {
            fn borrow(&self) -> &V {
                &self.0
            }
        }
    };
}

pub mod ark_serde {
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use serde::{Deserialize, Serialize};

    pub(crate) fn serialize<E, S>(e: &E, s: S) -> Result<S::Ok, S::Error>
    where
        E: CanonicalSerialize,
        S: serde::Serializer,
    {
        let mut bytes = Vec::new();
        e.serialize_compressed(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        bytes.serialize(s)
    }

    pub(crate) fn deserialize<'de, E, D>(d: D) -> Result<E, D::Error>
    where
        E: CanonicalDeserialize,
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(d)?;
        E::deserialize_compressed(&bytes[..]).map_err(serde::de::Error::custom)
    }
}
