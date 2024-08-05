use crate::schema::{
    CreateUserSchema, IdentifierWrapper, NoteHistoryRequest, NoteHistorySaved, NoteNullifierSchema,
    NullifierRequest, NullifierResponse, NullifierResponseData, SaveNoteHistoryRequestSchema, User,
    UserIdentifier, UsernameRequest,
};

use ark_bn254;
type TE = ark_ed_on_bn254::EdwardsConfig;
use ivcnotes::circuit::IVC;
use ivcnotes::service::msg;
use ivcnotes::Error;
use ivcnotes::FWrap;
use ivcnotes::{circuit::concrete::Concrete, service::Service};
use reqwest::{Method, Url};
use std::cell::RefCell;
use std::collections::HashMap;

pub enum HttpScheme {
    Http,
    Https,
}

enum Path {
    Register,
    GetContact,
    SendNote,
    GetNotes,
    CreateUser,
    GetUser,
    CreateAndTransferNoteHistory,
    GetNoteHistoryForUser,
    StoreNullifier,
    VerifyNullifier,
}

pub struct BlockingHttpClient {
    scheme: HttpScheme,
    host: String,
    port: Option<u16>,
    shared: RefCell<SharedState>,
}

type Field = <Concrete as IVC>::Field;

struct SharedState {
    contacts: HashMap<ivcnotes::Address<ark_bn254::Fr>, ivcnotes::wallet::Contact<Concrete>>,
}

fn send<Req: serde::Serialize, Res: for<'de> serde::Deserialize<'de>>(
    method: Method,
    url: Url,
    req: &Req,
) -> Result<Res, Error> {
    let client = reqwest::blocking::Client::new();
    let json = serde_json::to_string(&req).unwrap();
    let res = client
        .request(method, url)
        .header("Accept", "*/*")
        .header("Content-Type", "application/json")
        .body(json)
        .send()
        .map_err(|e| Error::Service(format!("Failed to send request: {}", e)))?;
    serde_json::from_reader(res)
        .map_err(|e| Error::Service(format!("Failed to convert response body: {}", e)))
}

impl BlockingHttpClient {
    pub fn new(scheme: HttpScheme, host: &str, port: Option<u16>) -> Self {
        Self {
            scheme,
            host: host.to_string(),
            port,
            shared: RefCell::new(SharedState {
                contacts: HashMap::new(),
            }),
        }
    }

    fn base(&self) -> Url {
        let scheme = match self.scheme {
            HttpScheme::Http => "http",
            HttpScheme::Https => "https",
        };
        let mut url = Url::parse(&format!("{}://{}", scheme, self.host)).unwrap();
        url.set_port(self.port).unwrap();
        url
    }

    fn path(&self, path: Path) -> Url {
        let mut url = self.base();
        let path = match path {
            Path::Register => "create_user",
            Path::GetContact => "get_contact",
            Path::GetNotes => "get_notes",
            Path::SendNote => "send_note",
            Path::CreateUser => "create_user",
            Path::GetUser => "get_user",
            Path::CreateAndTransferNoteHistory => "create_and_transfer_note_history",
            Path::GetNoteHistoryForUser => "get_note_history_for_user",
            Path::StoreNullifier => "store_nullifier",
            Path::VerifyNullifier => "verify_nullifier",
        };
        url.set_path(path);
        url
    }

    fn get_user_from_db(
        &self,
        identifier: UserIdentifier,
    ) -> Result<ivcnotes::wallet::Contact<Concrete>, String> {
        let url = self.path(Path::GetUser);
        let wrapper = IdentifierWrapper { identifier };
        let res: User =
            send(Method::GET, url, &wrapper).map_err(|e| format!("Failed to get user: {}", e))?;

        let address: ivcnotes::Address<ark_bn254::Fr> = match res.address {
            Some(ref address_str) => {
                let addy_byes = serde_json::from_str(address_str);
                let address =
                    ivcnotes::Address::from_bytes(addy_byes.expect("failed to deserialize"));
                address.expect("failed to return address")
            }
            None => return Err("User address is None".into()),
        };

        let pubkey: ivcnotes::PublicKey<TE> = match res.pubkey {
            Some(ref pubkey_str) => {
                let pubkey_bytes = serde_json::from_str(pubkey_str);
                let pubkey =
                    ivcnotes::PublicKey::from_bytes(pubkey_bytes.expect("failed to deserialize"));
                pubkey.expect("failed to return address")
            }
            None => return Err("User pubkey is None".into()),
        };

        Ok(ivcnotes::wallet::Contact {
            public_key: pubkey,
            address,
            username: res.username.ok_or("Username is None")?,
        })
    }

    pub fn store_nullifier(
        &self,
        nullifier: String,
        state: String,
        owner: String,
    ) -> Result<NullifierResponseData, String> {
        let nullifier_schema = NoteNullifierSchema {
            nullifier,
            state,
            owner,
            step: 1,
            note: "1".to_owned(),
        };

        let url = self.path(Path::StoreNullifier);
        let res: serde_json::Value = send(Method::POST, url, &nullifier_schema)
            .map_err(|e| format!("Failed to store nullifier: {}", e))?;

        let status = match res["status"].as_str() {
            Some("success") => "success",
            Some("not_found") => "not_found",
            _ => "error",
        };

        let nullifier = serde_json::from_value(res["nullifier"].clone())
            .map_err(|e| format!("Failed to parse nullifier: {}", e))?;

        Ok(NullifierResponseData { status, nullifier })
    }

    pub fn get_nullifier(
        &self,
        nullifier: String,
        expected_state: String,
    ) -> Result<NullifierResponse, String> {
        let nullifier_request = NullifierRequest {
            nullifier,
            state: expected_state,
        };

        let url = self.path(Path::VerifyNullifier);
        let result: Result<serde_json::Value, Error> = send(Method::GET, url, &nullifier_request);

        match result {
            Ok(json) => {
                let status = match json["status"].as_str() {
                    Some("success") => "success",
                    Some("not_found") => "not_found",
                    _ => "error",
                };

                let nullifier = serde_json::from_value(json["nullifier"].clone())
                    .map_err(|e| format!("Failed to parse nullifier: {}", e))?;

                let response_data = NullifierResponseData { status, nullifier };
                Ok(NullifierResponse::Ok(response_data.nullifier))
            }
            Err(Error::Service(e)) if e.contains("404 Not Found") => {
                Ok(NullifierResponse::NotFound)
            }
            Err(_) => Ok(NullifierResponse::Error),
        }
    }
}

impl Service<Concrete> for BlockingHttpClient {
    fn register(&self, msg: &msg::request::Register<Concrete>) -> Result<(), Error> {
        let address_bytes = msg.address.to_bytes();
        let pubkey_bytes = msg.address.to_bytes();

        let create_user_schema = CreateUserSchema {
            username: msg.username.clone(),
            // todo: round trip test needed
            address: serde_json::to_string(&address_bytes).expect("failed to serialize address"),
            pubkey: serde_json::to_string(&pubkey_bytes).expect("failed to serialize pubkey"),
            nonce: String::new(),
            messages: Vec::new(),
            notes: Vec::new(),
            has_double_spent: false,
        };

        let url = self.path(Path::CreateUser);
        send(Method::POST, url, &create_user_schema)
    }

    fn get_contact(
        &self,
        msg: &msg::request::GetContact<Field>,
    ) -> Result<msg::response::Contact<Concrete>, Error> {
        let mut shared = self.shared.borrow_mut();

        let contact = match msg {
            msg::request::GetContact::Username(username) => shared
                .contacts
                .values()
                .find(|contact| contact.username == *username)
                .cloned()
                .or_else(|| {
                    self.get_user_from_db(UserIdentifier::Username(username.clone()))
                        .ok()
                }),
            msg::request::GetContact::Address(address) => {
                shared.contacts.get(address).cloned().or_else(|| {
                    let address_bytes = address.to_bytes();
                    let smtg_address =
                        serde_json::to_string(&address_bytes).expect("failed to serialize address");
                    let address_json = serde_json::to_string(&smtg_address).unwrap();
                    self.get_user_from_db(UserIdentifier::Address(address_json))
                        .ok()
                })
            }
        };

        match contact {
            Some(contact) => {
                shared
                    .contacts
                    .entry(contact.address)
                    .or_insert_with(|| contact.clone());
                Ok(contact)
            }
            None => Err(Error::Service("broken".to_owned())),
        }
    }

    fn send_note(&self, msg: &msg::request::Note<Concrete>) -> Result<(), Error> {
        let address_bytes = msg.receiver.to_bytes();
        let address_json =
            serde_json::to_string(&address_bytes).expect("failed to serialize address");

        let send_and_transfer_json = NoteHistoryRequest {
            owner_username: None,
            recipient_username: "user0".to_owned(),
            note_history: SaveNoteHistoryRequestSchema {
                data: msg.note_history.encrypted.data.clone(),
                address: address_json,
            },
            message: "Transfer".to_string(),
        };

        let url = self.path(Path::CreateAndTransferNoteHistory);
        send(Method::POST, url, &send_and_transfer_json)
    }

    fn get_notes(
        &self,
        msg: &msg::request::GetNotes<Field>,
    ) -> Result<msg::response::Notes<Concrete>, Error> {
        let username_request = UsernameRequest {
            username: "user0".to_owned(),
        };

        let url = self.path(Path::GetNoteHistoryForUser);
        let note_history: Vec<NoteHistorySaved> = send(Method::GET, url, &username_request)?;

        let encrypted_note_history: Vec<ivcnotes::note::EncryptedNoteHistory<Concrete>> =
            note_history
                .into_iter()
                .map(|nh| {
                    self.convert_note_history_to_encrypted_note_history(nh, "user0".to_owned())
                })
                .collect();

        Ok(msg::response::Notes {
            notes: encrypted_note_history,
        })
    }
}

impl BlockingHttpClient {
    fn convert_note_history_to_encrypted_note_history(
        &self,
        nh: NoteHistorySaved,
        username: String,
    ) -> ivcnotes::note::EncryptedNoteHistory<Concrete> {
        let contact = self
            .get_user_from_db(UserIdentifier::Username(username))
            .expect("couldn't get contact");

        ivcnotes::note::EncryptedNoteHistory {
            sender: contact,
            encrypted: ivcnotes::cipher::EncryptedData { data: nh.data },
        }
    }
}
