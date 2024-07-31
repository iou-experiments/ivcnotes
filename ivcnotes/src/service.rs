use crate::{
    circuit::IVC,
    note::{EncryptedNoteHistory, NoteHistory},
    wallet::{Contact, Wallet},
    Address, Error,
};

pub struct Comm<E: IVC> {
    pub(crate) service: Box<dyn Service<E>>,
}

pub trait Service<E: IVC> {
    fn register(&self, msg: &msg::request::Register<E>) -> Result<(), crate::Error>;
    fn get_contact(
        &self,
        msg: &msg::request::GetContact<E::Field>,
    ) -> Result<msg::response::Contact<E>, crate::Error>;
    fn send_note(&self, msg: &msg::request::Note<E>) -> Result<(), crate::Error>;
    fn get_notes(
        &self,
        msg: &msg::request::GetNotes<E::Field>,
    ) -> Result<msg::response::Notes<E>, crate::Error>;
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
        pub struct Note<E: IVC> {
            pub note_history: EncryptedNoteHistory<E>,
            #[serde(with = "crate::ark_serde")]
            pub receiver: Address<E::Field>,
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
        pub struct Notes<E: IVC> {
            pub notes: Vec<EncryptedNoteHistory<E>>,
        }
    }
}

impl<E: IVC> Wallet<E> {
    pub fn register(&self) -> Result<(), crate::Error> {
        let contact = self.contact();
        self.comm.service.register(&contact)
    }

    pub fn find_contact_by_username(&mut self, username: &str) -> Result<Contact<E>, crate::Error> {
        match self.address_book.find_username(username) {
            Some(contact) => Ok(contact.clone()),
            None => {
                let msg = msg::request::GetContact::Username(username.to_string());
                let contact = self.comm.service.get_contact(&msg)?;
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
                let msg = msg::request::GetContact::Address(*address);
                let contact = self.comm.service.get_contact(&msg)?;
                self.address_book.new_contact(&contact);
                Ok(contact)
            }
        }
    }
}

impl<E: IVC> Wallet<E> {
    pub(crate) fn send_note(
        &mut self,
        receiver: &Contact<E>,
        note_history: &NoteHistory<E>,
    ) -> Result<(), crate::Error> {
        let encrypted = self.auth.encrypt(&receiver.public_key, note_history);
        let note_history = EncryptedNoteHistory {
            encrypted,
            sender: self.contact(),
        };
        let msg = msg::request::Note {
            note_history,
            receiver: receiver.address,
        };
        self.comm.service.send_note(&msg)
    }

    pub fn get_notes(&mut self) -> Result<(), crate::Error> {
        let msg = msg::request::GetNotes {
            receiver: *self.address(),
        };
        let notes = self.comm.service.get_notes(&msg)?;
        let note_histories: Vec<NoteHistory<E>> = notes
            .notes
            .into_iter()
            .map(|note_history| {
                let sender = note_history.sender;
                self.auth
                    .decrypt(&sender.public_key, &note_history.encrypted)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        // TODO: continue iteration even some note_history fail
        for note_history in note_histories.iter() {
            self.verify_incoming(note_history)?;
        }

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::Service;
    use crate::{
        circuit::{test::ConcreteIVC, IVC},
        note::EncryptedNoteHistory,
        wallet::Contact,
        Address,
    };
    use ark_bn254::Fr;
    use ark_ec::twisted_edwards::TECurveConfig;
    use ark_ed_on_bn254::EdwardsConfig;
    use ark_serialize::CanonicalSerialize;
    use arkeddsa::PublicKey;
    use serde_derive::{Deserialize, Serialize};
    use std::{cell::RefCell, collections::HashMap, rc::Rc};
    type TE = EdwardsConfig;
    use arkeddsa::SigningKey;
    use rand_core::OsRng;

    #[derive(Clone)]
    pub struct MockService {
        contacts: HashMap<Address<Fr>, Contact<ConcreteIVC>>,
        last_access: HashMap<Address<Fr>, usize>,
        queue: HashMap<Address<Fr>, Vec<EncryptedNoteHistory<ConcreteIVC>>>,
    }

    #[derive(Clone)]
    pub struct SharedMockService {
        pub shared: Rc<RefCell<MockService>>,
    }

    impl SharedMockService {
        pub(crate) fn new() -> SharedMockService {
            SharedMockService {
                shared: Rc::new(RefCell::new(MockService {
                    contacts: HashMap::new(),
                    last_access: HashMap::new(),
                    queue: HashMap::new(),
                })),
            }
        }

        pub(crate) fn clone(&self) -> Self {
            Self {
                shared: Rc::clone(&self.shared),
            }
        }

        pub(crate) fn log_contacts(&self) {
            let shared = self.shared.borrow();
            for contact in shared.contacts.values() {
                println!("{:?}", contact);
            }
        }

        pub(crate) fn log_messages(&self) {
            let shared = self.shared.borrow();
            for (address, messages) in shared.queue.iter() {
                println!("msg for {:?}", address);
                for message in messages {
                    println!(
                        "sender {:?}, len: {}",
                        message.sender.username,
                        message.encrypted.data.len()
                    );
                }
            }
        }
    }

    #[derive(Serialize, Deserialize)]
    pub struct SmtgWithPubkey<TE: TECurveConfig> {
        #[serde(with = "crate::ark_serde")]
        pubkey: PublicKey<TE>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct SmtgWithAddress<E: IVC> {
        #[serde(with = "crate::ark_serde")]
        address: Address<E::Field>,
    }

    // fn ser_address<E: IVC>(address: &Address<E> + ark_ff::PrimeField) -> Vec<u8> {
    //     let mut bytes = Vec::new();
    //     address.serialize_compressed(&mut bytes).unwrap();
    //     bytes
    // }

    fn ser_smtg_with_address<E: IVC>(smtg: SmtgWithAddress<E>) -> Vec<u8> {
        bincode::serialize(&smtg).unwrap()
    }

    fn ser_pubkey<TE: TECurveConfig>(pubkey: &PublicKey<TE>) -> Vec<u8> {
        let mut bytes = Vec::new();
        pubkey.serialize_compressed(&mut bytes).unwrap();
        bytes
    }

    fn ser_smtg_with_pubkey<TE: TECurveConfig>(smtg: SmtgWithPubkey<TE>) -> Vec<u8> {
        bincode::serialize(&smtg).unwrap()
    }

    impl Service<ConcreteIVC> for SharedMockService {
        fn register(
            &self,
            msg: &super::msg::request::Register<ConcreteIVC>,
        ) -> Result<(), crate::Error> {
            let sk: SigningKey<TE> = SigningKey::generate::<sha2::Sha512>(&mut OsRng).unwrap();
            let pubkey = sk.public_key().clone();
            // serialization with crate::serde
            let smtg_pubkey = SmtgWithPubkey { pubkey };
            let smtg_address = SmtgWithAddress::<ConcreteIVC> {
                address: msg.address,
            };
            let pubkey_bytes = ser_smtg_with_pubkey(smtg_pubkey);
            let address_bytes = ser_smtg_with_address(smtg_address);
            let contact = Contact {
                address: msg.address,
                username: msg.username.clone(),
                public_key: msg.public_key.clone(),
            };
            let client = reqwest::blocking::Client::new();

            let create_user_schema = crate::service_schema::CreateUserSchema {
                username: msg.username.clone(),
                address: hex::encode(address_bytes),
                pubkey: hex::encode(pubkey_bytes),
                nonce: String::new(), // You might want to generate a nonce
                messages: Vec::new(),
                notes: Vec::new(),
                has_double_spent: false,
            };

            let json_body = serde_json::to_string(&create_user_schema)
                .expect("Failed to serialize CreateUserSchema");

            let _ = client
                .post("http://167.172.25.99:80/create_user")
                .header("Accept", "*/*")
                .header("Content-Type", "application/json")
                .body(json_body)
                .send();

            let mut shared = self.shared.borrow_mut();
            shared.contacts.insert(msg.address, contact);
            Ok(())
        }

        fn get_contact(
            &self,
            msg: &super::msg::request::GetContact<Fr>,
        ) -> Result<super::msg::response::Contact<ConcreteIVC>, crate::Error> {
            match msg {
                super::msg::request::GetContact::Username(username) => {
                    let shared = self.shared.borrow();
                    let contact = shared
                        .contacts
                        .values()
                        .find(|contact| contact.username == *username)
                        .ok_or(crate::Error::With("contact not found"))?;
                    Ok(contact.clone())
                }
                super::msg::request::GetContact::Address(address) => {
                    let shared = self.shared.borrow();
                    let contact = shared
                        .contacts
                        .get(address)
                        .ok_or(crate::Error::With("contact not found"))?;
                    Ok(contact.clone())
                }
            }
        }

        fn send_note(
            &self,
            msg: &super::msg::request::Note<ConcreteIVC>,
        ) -> Result<(), crate::Error> {
            let mut shared = self.shared.borrow_mut();
            shared
                .queue
                .entry(msg.receiver)
                .or_default()
                .push(msg.note_history.clone());
            Ok(())
        }

        fn get_notes(
            &self,
            msg: &super::msg::request::GetNotes<Fr>,
        ) -> Result<super::msg::response::Notes<ConcreteIVC>, crate::Error> {
            let shared = self.shared.borrow();
            let last_access = shared.last_access.get(&msg.receiver).unwrap_or(&0);
            let notes = shared
                .queue
                .get(&msg.receiver)
                .unwrap_or(&vec![])
                .iter()
                .skip(*last_access)
                .cloned()
                .collect::<Vec<_>>();
            Ok(super::msg::response::Notes { notes })
        }
    }
}
