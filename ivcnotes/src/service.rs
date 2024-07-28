use crate::{
    circuit::IVC,
    note::NoteHistory,
    wallet::{Contact, Wallet},
    Address, Error,
};

pub struct Comm<E: IVC> {
    pub(crate) name_server: Box<dyn NameServer<E>>,
    pub(crate) message_server: Box<dyn MessageServer<E>>,
}

// response request messages between server and client
pub mod msg {
    pub mod request {
        use crate::{cipher::EncryptedNoteHistory, Address};
        use ark_ec::twisted_edwards::TECurveConfig;
        use ark_ff::PrimeField;
        use arkeddsa::{signature::Signature, PublicKey};
        use serde_derive::{Deserialize, Serialize};

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct Register<TE: TECurveConfig + Clone> {
            pub username: String,
            #[serde(with = "crate::ark_serde")]
            pub public_key: PublicKey<TE>,
            #[serde(with = "crate::ark_serde")]
            pub signature: Signature<TE>,
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub enum Contact<F: PrimeField> {
            Username(String),
            #[serde(with = "crate::ark_serde")]
            Address(Address<F>),
        }

        pub struct Note<F: PrimeField> {
            pub note_history: EncryptedNoteHistory,
            pub receiver: Address<F>,
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct Empty {}
    }

    pub mod response {

        use crate::{cipher::EncryptedNoteHistory, Address};
        use ark_ff::PrimeField;
        use serde_derive::{Deserialize, Serialize};

        pub type Contact<E> = crate::wallet::Contact<E>;

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct Notes<F: PrimeField> {
            #[serde(with = "crate::ark_serde")]
            pub sender: Address<F>,
            pub notes: Vec<EncryptedNoteHistory>,
        }
    }
}

pub trait NameServer<E: IVC> {
    fn register(&self, msg: &msg::request::Register<E::TE>) -> Result<(), crate::Error>;
    fn get_contact(
        &self,
        msg: &msg::request::Contact<E::Field>,
    ) -> Result<msg::response::Contact<E>, crate::Error>;
}

impl<E: IVC> Wallet<E> {
    pub fn register(&self, username: &str) -> Result<(), crate::Error> {
        let username_data = username.as_bytes();
        let signature = self.auth.sign(&[username_data]);
        let public_key = self.auth.public_key();

        let msg = msg::request::Register {
            username: username.to_string(),
            public_key: public_key.clone(),
            signature: signature.clone(),
        };

        self.comm.name_server.register(&msg)
    }

    pub fn find_contact_by_username(&mut self, username: &str) -> Result<Contact<E>, crate::Error> {
        match self.address_book.find_username(username) {
            Some(contact) => Ok(contact.clone()),
            None => {
                let msg = msg::request::Contact::Username(username.to_string());
                let contact = self.comm.name_server.get_contact(&msg)?;
                self.address_book.new_contact(&contact);
                Ok(contact)
            }
        }
    }

    pub fn find_contact_by_address(
        &mut self,
        address: &Address<E::Field>,
    ) -> Result<Contact<E>, crate::Error> {
        match self.address_book.find_address(address) {
            Some(contact) => Ok(contact.clone()),
            None => {
                let msg = msg::request::Contact::Address(*address);
                let contact = self.comm.name_server.get_contact(&msg)?;
                self.address_book.new_contact(&contact);
                Ok(contact)
            }
        }
    }
}

pub trait MessageServer<E: IVC> {
    fn send_note(&self, msg: &msg::request::Note<E::Field>) -> Result<(), crate::Error>;
    fn get_notes(
        &self,
        msg: &msg::request::Empty,
    ) -> Result<msg::response::Notes<E::Field>, crate::Error>;
}

impl<E: IVC> Wallet<E> {
    pub fn send_note(
        &mut self,
        receiver: &Contact<E>,
        note_history: &NoteHistory<E>,
    ) -> Result<(), crate::Error> {
        let note_history = self.auth.encrypt(&receiver.public_key, note_history);
        let msg = msg::request::Note {
            note_history,
            receiver: receiver.address,
        };
        self.comm.message_server.send_note(&msg)
    }

    pub fn get_notes(&mut self) -> Result<(), crate::Error> {
        let notes = self
            .comm
            .message_server
            .get_notes(&msg::request::Empty {})?;
        let sender = &notes.sender;
        let contact = self.find_contact_by_address(sender)?;

        let note_histories: Vec<NoteHistory<E>> = notes
            .notes
            .into_iter()
            .map(|note_history| self.auth.decrypt(&contact.public_key, &note_history))
            .collect::<Result<Vec<_>, Error>>()?;

        // TODO: continue iteration even some note_history fail
        for note_history in note_histories.iter() {
            self.verify_incoming(note_history)?;
        }

        Ok(())
    }
}
