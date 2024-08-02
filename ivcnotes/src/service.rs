use crate::{
    circuit::IVC,
    note::{EncryptedNoteHistory, NoteHistory},
    service_schema::{NoteHistorySaved, UserIdentifier},
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
    ) -> Result<msg::response::Notes<E>, String>;
    fn get_user_from_db(&self, identifier: UserIdentifier) -> Result<Contact<E>, String>;
    fn convert_note_history_to_encrypted_note_history(
        &self,
        nh: NoteHistorySaved,
        username: String,
    ) -> EncryptedNoteHistory<E>;
    fn store_nullifier(
        &self,
        nullifier: String,
        state: String,
        owner: String,
    ) -> Result<crate::service_schema::NullifierResponseData, String>;
    fn get_nullifier(
        &self,
        nullifier: String,
        expected_state: String,
    ) -> Result<crate::service_schema::NullifierResponse, String>;
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
            pub username: String,
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct GetNotes<F: PrimeField> {
            #[serde(with = "crate::ark_serde")]
            pub receiver: Address<F>,
            pub username: String,
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

    pub fn get_user_from_db(&mut self, identifier: UserIdentifier) -> Result<Contact<E>, String> {
        self.comm.service.get_user_from_db(identifier)
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
        address: &Address<<E as crate::circuit::IVC>::Field>,
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
            username: receiver.username.clone(),
            receiver: receiver.address,
        };
        self.comm.service.send_note(&msg)
    }

    pub fn get_notes(&mut self) -> Result<(), crate::Error> {
        let msg = msg::request::GetNotes {
            receiver: *self.address(),
            username: self.username.to_string(),
        };
        let notes = self
            .comm
            .service
            .get_notes(&msg)
            .expect("failed to get notes from db");

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
        circuit::test::ConcreteIVC,
        note::EncryptedNoteHistory,
        service_schema::{
            IdentifierWrapper, NullifierRequest, SaveNoteHistoryRequestSchema, User, UserIdentifier,
        },
        wallet::Contact,
        Address,
    };
    use ark_bn254::Fr;
    use ark_ec::twisted_edwards::TECurveConfig;
    use ark_ed_on_bn254::EdwardsConfig;
    use arkeddsa::PublicKey;
    use serde_derive::{Deserialize, Serialize};
    use std::{cell::RefCell, collections::HashMap, rc::Rc};
    type TE = EdwardsConfig;
    use ark_ff::PrimeField;
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

    #[derive(Serialize, Deserialize, Debug)]
    pub struct SmtgWithPubkey<TE: TECurveConfig> {
        #[serde(with = "crate::ark_serde")]
        pubkey: PublicKey<TE>,
    }

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    pub struct SmtgWithAddress<F: PrimeField> {
        #[serde(with = "crate::ark_serde")]
        address: Address<F>,
    }

    impl Service<ConcreteIVC> for SharedMockService {
        fn register(
            &self,
            msg: &super::msg::request::Register<ConcreteIVC>,
        ) -> Result<(), crate::Error> {
            let pubkey = msg.public_key.clone();
            // serialization with crate::serde
            let smtg_pubkey = SmtgWithPubkey { pubkey };
            let smtg_address = SmtgWithAddress {
                address: msg.address,
            };
            let pubkey_json = serde_json::to_string(&smtg_pubkey).unwrap();
            let address_json = serde_json::to_string(&smtg_address).unwrap();

            let client = reqwest::blocking::Client::new();

            let create_user_schema = crate::service_schema::CreateUserSchema {
                username: msg.username.clone(),
                address: address_json,
                pubkey: pubkey_json,
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
            Ok(())
        }

        fn get_user_from_db(
            &self,
            identifier: UserIdentifier,
        ) -> Result<Contact<crate::circuit::test::ConcreteIVC>, String> {
            let client = reqwest::blocking::Client::new();
            let wrapper = IdentifierWrapper { identifier };
            let json_body = serde_json::to_string(&wrapper).expect("Failed to serialize to json");
            let res = client
                .get("http://167.172.25.99/get_user")
                .header("Accept", "*/*")
                .header("Content-Type", "application/json")
                .body(json_body)
                .send()
                .map_err(|e| format!("Failed to send request: {}", e))?;

            if res.status().is_success() {
                let res_text = res
                    .text()
                    .map_err(|e| format!("Failed to read response body: {}", e));

                let user: User = serde_json::from_str(&res_text.unwrap()).unwrap();
                let address: Address<ark_bn254::Fr> = match user.address {
                    Some(ref address_str) => {
                        let smtg: SmtgWithAddress<ark_bn254::Fr> =
                            serde_json::from_str(address_str).expect("no address");
                        smtg.address
                    }
                    None => return Err("User address is None".into()),
                };

                let pubkey: PublicKey<TE> = match user.pubkey {
                    Some(ref pubkey_str) => {
                        println!("string of pubkey, {:#?}", pubkey_str);
                        let smtg: SmtgWithPubkey<TE> =
                            serde_json::from_str(pubkey_str).expect("no pubkey");
                        smtg.pubkey
                    }
                    None => return Err("User pubkey is None".into()),
                };

                let contact = Contact {
                    public_key: pubkey,
                    address,
                    username: user.username.ok_or("Username is None")?,
                };

                Ok(contact)
            } else {
                Err(format!("Request failed with status: {}", res.status()))
            }
        }

        fn get_contact(
            &self,
            msg: &super::msg::request::GetContact<Fr>,
        ) -> Result<super::msg::response::Contact<ConcreteIVC>, crate::Error> {
            let mut shared = self.shared.borrow_mut(); // Note: changed to mutable borrow

            let contact = match msg {
                super::msg::request::GetContact::Username(username) => {
                    println!("{:#?}, {:#?}", msg, username);
                    shared
                        .contacts
                        .values()
                        .find(|contact| contact.username == *username)
                        .cloned()
                        .or_else(|| {
                            // Fetch from DB if not in shared
                            self.get_user_from_db(crate::service_schema::UserIdentifier::Username(
                                username.clone(),
                            ))
                            .ok()
                        })
                }
                super::msg::request::GetContact::Address(address) => {
                    println!("{:#?}, {:#?}", msg, address);
                    shared.contacts.get(address).cloned().or_else(|| {
                        let smtg_address = SmtgWithAddress { address: *address };
                        let address_json = serde_json::to_string(&smtg_address).unwrap();
                        self.get_user_from_db(crate::service_schema::UserIdentifier::Address(
                            address_json,
                        ))
                        .ok()
                    })
                }
            };

            match contact {
                Some(contact) => {
                    // Add the contact to shared if it wasn't there before
                    shared
                        .contacts
                        .entry(contact.address)
                        .or_insert_with(|| contact.clone());
                    Ok(contact)
                }
                None => Err(crate::Error::With("contact not found")),
            }
        }

        fn send_note(
            &self,
            msg: &super::msg::request::Note<ConcreteIVC>,
        ) -> Result<(), crate::Error> {
            let client = reqwest::blocking::Client::new();
            let smtg_address = SmtgWithAddress {
                address: msg.receiver,
            };
            let address_json = serde_json::to_string(&smtg_address).unwrap();

            let send_and_transfer_json = crate::service_schema::NoteHistoryRequest {
                owner_username: None,
                recipient_username: msg.username.clone(),
                note_history: SaveNoteHistoryRequestSchema {
                    data: msg.note_history.encrypted.data.clone(),
                    address: address_json,
                },
                message: "Transfer".to_string(),
            };

            let json_body = serde_json::to_string(&send_and_transfer_json)
                .expect("Failed to serialize Notehistory");

            let res = client
                .post("http://167.172.25.99/create_and_transfer_note_history")
                .header("Accept", "*/*")
                .header("Content-Type", "application/json")
                .body(json_body)
                .send()
                .map_err(|e| format!("Failed to send request: {}", e));

            println!("{:#?}", res);

            Ok(())
        }

        fn get_notes(
            &self,
            msg: &super::msg::request::GetNotes<Fr>,
        ) -> Result<super::msg::response::Notes<ConcreteIVC>, String> {
            let client = reqwest::blocking::Client::new();

            let username_request = crate::service_schema::UsernameRequest {
                username: msg.username.clone(), // Assuming receiver is the username we want to fetch notes for
            };

            let json_body = serde_json::to_string(&username_request)
                .expect("Failed to serialize UsernameRequest");

            let res = client
                .get("http://167.172.25.99/get_note_history_for_user") // Adjust the URL as needed
                .header("Accept", "*/*")
                .header("Content-Type", "application/json")
                .body(json_body)
                .send()
                .map_err(|e| format!("Failed to send request: {}", e))
                .expect("no client");

            if res.status().is_success() {
                let res_text = res
                    .text()
                    .map_err(|e| format!("Failed to read response body: {}", e));

                let note_history: Vec<crate::service_schema::NoteHistorySaved> =
                    serde_json::from_str(&res_text.unwrap()).unwrap();

                let encrypted_note_history: Vec<EncryptedNoteHistory<ConcreteIVC>> = note_history
                    .into_iter()
                    .map(|nh| {
                        self.convert_note_history_to_encrypted_note_history(
                            nh,
                            msg.username.clone(),
                        )
                    })
                    .collect();

                Ok(super::msg::response::Notes {
                    notes: encrypted_note_history,
                })
            } else {
                Err(format!("Request failed with status: {}", res.status()))
            }
        }

        fn convert_note_history_to_encrypted_note_history(
            &self,
            nh: crate::service_schema::NoteHistorySaved,
            username: String,
        ) -> EncryptedNoteHistory<ConcreteIVC> {
            // Parse the address string to extract sender information
            let contact = self
                .get_user_from_db(crate::service_schema::UserIdentifier::Username(
                    username.clone(),
                ))
                .expect("couldn't get contact");
            println!("{:#?}", contact);
            EncryptedNoteHistory {
                sender: contact,
                encrypted: crate::cipher::EncryptedData { data: nh.data },
            }
        }

        fn store_nullifier(
            &self,
            nullifier: String,
            state: String,
            owner: String,
        ) -> Result<crate::service_schema::NullifierResponseData, String> {
            let client = reqwest::blocking::Client::new();

            let nullifier_schema = crate::service_schema::NoteNullifierSchema {
                nullifier,
                state,
                owner,
                step: 1,
                note: "1".to_owned(),
            };

            let json_body = serde_json::to_string(&nullifier_schema)
                .expect("Failed to serialize NoteNullifierSchema");

            let res = client
                .post("http://167.172.25.99/store_nullifier")
                .header("Accept", "*/*")
                .header("Content-Type", "application/json")
                .body(json_body)
                .send()
                .map_err(|e| format!("Failed to send request: {}", e))
                .expect("failed to store");

            if res.status().is_success() {
                let response_text = res
                    .text()
                    .map_err(|e| format!("Failed to read response body: {}", e))?;

                let mut json: serde_json::Value = serde_json::from_str(&response_text)
                    .map_err(|e| format!("Failed to parse JSON: {}", e))?;

                // Convert the status to a static str
                let status = match json["status"].as_str() {
                    Some("success") => "success",
                    Some("not_found") => "not_found",
                    _ => "error",
                };

                let nullifier = serde_json::from_value(json["nullifier"].take())
                    .map_err(|e| format!("Failed to parse nullifier: {}", e))?;

                Ok(crate::service_schema::NullifierResponseData { status, nullifier })
            } else {
                Err(format!("Request failed with status: {}", res.status()))
            }
        }

        fn get_nullifier(
            &self,
            nullifier: String,
            expected_state: String,
        ) -> Result<crate::service_schema::NullifierResponse, String> {
            let client = reqwest::blocking::Client::new();
            let json_body = serde_json::to_string(&crate::service_schema::NullifierRequest {
                nullifier,
                state: expected_state,
            })
            .expect("couldn't serialize nullifier request");

            let res = client
                .get("http://167.172.25.99/verify_nullifier/")
                .header("Accept", "*/*")
                .header("Content-Type", "application/json")
                .body(json_body)
                .send()
                .map_err(|e| format!("Failed to send request: {}", e))?;

            if res.status().is_success() {
                let response_text = res
                    .text()
                    .map_err(|e| format!("Failed to read response body: {}", e))?;

                let mut json: serde_json::Value = serde_json::from_str(&response_text)
                    .map_err(|e| format!("Failed to parse JSON: {}", e))?;

                // Convert the status to a static str
                let status = match json["status"].as_str() {
                    Some("success") => "success",
                    Some("not_found") => "not_found",
                    _ => "error",
                };

                let nullifier = serde_json::from_value(json["nullifier"].take())
                    .map_err(|e| format!("Failed to parse nullifier: {}", e))?;

                let response_data =
                    crate::service_schema::NullifierResponseData { status, nullifier };
                Ok(crate::service_schema::NullifierResponse::Ok(
                    response_data.nullifier,
                ))
            } else if res.status() == reqwest::StatusCode::NOT_FOUND {
                Ok(crate::service_schema::NullifierResponse::NotFound)
            } else {
                Ok(crate::service_schema::NullifierResponse::Error)
            }
        }
    }
}
