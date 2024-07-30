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
pub mod service;
pub mod tx;
pub mod wallet;

crate::field_wrap!(SigHash);
crate::field_wrap!(Address);
crate::field_wrap!(NullifierKey);
crate::field_wrap!(Nullifier);
crate::field_wrap!(StateHash);
crate::field_wrap!(AssetHash);
crate::field_wrap!(Blind);
crate::field_wrap!(NoteHash);
crate::field_wrap!(BlindNoteHash);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    With(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            Self::With(s) => write!(f, "{}", s),
        }
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

    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn ark_std::error::Error>> {
        let deserialized = F::deserialize_compressed(bytes)?;
        Ok(deserialized.into())
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
                let bytes = self.to_bytes();
                write!(f, "0x")?;
                bytes.iter().rev().try_for_each(|&b| write!(f, "{:02x}", b))
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
