pub mod asset;
pub mod crypto;
pub mod id;
pub mod note;
pub mod tx;
pub mod wallet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    With(&'static str),
    Serialization,
}

trait FWrap<F: ark_ff::PrimeField>: From<F> + AsRef<F> {
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
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let deserialized = F::deserialize_compressed(bytes).map_err(|_| Error::Serialization)?;
        Ok(deserialized.into())
    }
    fn reduce_bytes(bytes: &[u8]) -> Self {
        F::from_le_bytes_mod_order(bytes).into()
    }
}

#[macro_export]
macro_rules! field_wrap {
    ($name:ident) => {
        #[derive(Clone, Debug, Copy, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
        pub struct $name<F: ark_ff::PrimeField>(F);

        impl<F: ark_ff::PrimeField> From<F> for $name<F> {
            fn from(value: F) -> Self {
                Self(value)
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
    };
}
