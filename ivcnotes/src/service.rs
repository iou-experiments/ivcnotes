use crate::circuit::IVC;
use crate::Address;
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ff::PrimeField;
use arkeddsa::PublicKey;
use serde_derive::{Deserialize, Serialize};

#[derive(serde_derive::Serialize, serde_derive::Deserialize, Debug)]
pub struct SmtgWithPubkey<TE: ark_ec::twisted_edwards::TECurveConfig> {
    #[serde(with = "crate::ark_serde")]
    pub pubkey: crate::PublicKey<TE>,
}

pub trait Service<E: IVC> {
    fn register(&self, msg: &msg::request::Register<E>) -> Result<(), crate::Error>;
    fn get_contact(
        &self,
        msg: &msg::request::GetContact<E::Field>,
    ) -> Result<msg::response::Contact<E>, crate::Error>;
    fn send_note(&self, msg: &msg::request::SendNote<E>) -> Result<(), crate::Error>;
    fn get_notes(
        &self,
        msg: &msg::request::GetNotes<E::Field>,
    ) -> Result<msg::response::Notes<E>, crate::Error>;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SmtgWithPubkey<TE: TECurveConfig> {
    #[serde(with = "crate::ark_serde")]
    pub pubkey: PublicKey<TE>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct SmtgWithAddress<F: PrimeField> {
    #[serde(with = "crate::ark_serde")]
    pub address: Address<F>,
}

// response request messages between server and client
pub mod msg {
    pub mod request {
        use crate::{circuit::IVC, note::EncryptedNoteHistory, Address};
        use ark_ff::PrimeField;
        use serde_derive::{Deserialize, Serialize};

        pub type Register<E> = crate::wallet::Contact<E>;

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub enum GetContact<F: PrimeField> {
            Username(String),
            #[serde(with = "crate::ark_serde")]
            Address(Address<F>),
        }

        #[derive(Clone, Serialize, Deserialize)]
        #[serde(bound = "E: IVC")]
        pub struct SendNote<E: IVC> {
            pub note_history: EncryptedNoteHistory<E>,
            #[serde(with = "crate::ark_serde")]
            pub receiver: Address<E::Field>,
            pub receiver_username: String,
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct GetNotes<F: PrimeField> {
            #[serde(with = "crate::ark_serde")]
            pub receiver: Address<F>,
        }
    }

    pub mod response {
        use crate::{circuit::IVC, note::EncryptedNoteHistory};
        use serde_derive::{Deserialize, Serialize};

        pub type Contact<E> = crate::wallet::Contact<E>;

        #[derive(Clone, Serialize, Deserialize)]
        #[serde(bound = "E: IVC")]
        pub struct Notes<E: IVC> {
            pub notes: Vec<EncryptedNoteHistory<E>>,
        }
    }
}
