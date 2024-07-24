use ark_ff::PrimeField;
use std::borrow::Borrow;

pub mod asset;
pub mod circuit;
// pub mod cs;
pub mod id;
pub mod note;
pub mod poseidon;
pub mod tx;
pub mod wallet;

// Wraps a field element with additional functionality
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

// Trait to add functionality to wrapped field elements
pub trait FWrap<F: ark_ff::PrimeField>: From<F> + AsRef<F> {
    // Returns the inner field element
    fn inner(&self) -> F;

    // Generates a random instance of the wrapped field element
    fn rand(rng: &mut impl rand::RngCore) -> Self {
        F::rand(rng).into()
    }

    // Hashes the field element using the provided digest
    fn hash<D: digest::Digest>(&self) -> Vec<u8> {
        use ark_serialize::CanonicalSerializeHashExt;
        self.inner().hash_uncompressed::<D>().to_vec()
    }

    // Serializes the field element to bytes
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.inner().serialize_compressed(&mut bytes).unwrap();
        bytes
    }

    // Deserializes a field element from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn ark_std::error::Error>> {
        let deserialized = F::deserialize_compressed(bytes)?;
        Ok(deserialized.into())
    }

    // Reduces bytes to a field element
    fn reduce_bytes(bytes: &[u8]) -> Self {
        F::from_le_bytes_mod_order(bytes).into()
    }
}

#[macro_export]
macro_rules! field_wrap {
    ($name:ident) => {
        #[derive(Clone, Debug, Copy, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
        pub struct $name<F: ark_ff::PrimeField>(F);

        // Conversion from a field element to the wrapped type
        impl<F: ark_ff::PrimeField> From<F> for $name<F> {
            fn from(value: F) -> Self {
                Self(value)
            }
        }

        // Conversion from a reference to a field element to the wrapped type
        impl<F: ark_ff::PrimeField> From<&F> for $name<F> {
            fn from(value: &F) -> Self {
                Self(*value)
            }
        }

        // Accessing the inner field element
        impl<F: ark_ff::PrimeField> AsRef<F> for $name<F> {
            fn as_ref(&self) -> &F {
                &self.0
            }
        }

        // Implementing the FWrap trait for the wrapped type
        impl<F: ark_ff::PrimeField> FWrap<F> for $name<F> {
            fn inner(&self) -> F {
                self.0
            }
        }

        // Borrowing the inner field element
        impl<V: PrimeField> Borrow<V> for $name<V> {
            fn borrow(&self) -> &V {
                &self.0
            }
        }
    };
}
