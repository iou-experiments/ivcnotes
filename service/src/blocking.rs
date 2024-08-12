use crate::schema::{
    CreateUserSchema, IdentifierWrapper, NoteHistoryRequest, NoteHistorySaved, NoteNullifierSchema,
    NullifierRequest, NullifierResponseData, SaveNoteHistoryRequestSchema, User, UserIdentifier,
};
type TE = ark_ed_on_bn254::EdwardsConfig;
use ivcnotes::circuit::concrete::Concrete;
use ivcnotes::service::msg;
use ivcnotes::service::msg::response::Contact;
use ivcnotes::service::{SmtgWithAddress, SmtgWithPubkey};
use ivcnotes::Error;
use ivcnotes::FWrap;
use ivcnotes::{Address, PublicKey};
use reqwest::{Method, Url};
pub enum HttpScheme {
    Http,
    Https,
}
enum Path {
    CreateUser,
    GetUser,
    CreateAndTransferNoteHistory,
    GetNoteHistoryForUser,
    StoreNullifier,
    VerifyNullifier,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Sender {
    pub username: String,
}

use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedNoteHistory {
    pub receiver: User,
    pub encrypted: ivcnotes::cipher::EncryptedData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Notes {
    pub notes: Vec<EncryptedNoteHistory>,
}

pub struct BlockingHttpClient {
    scheme: HttpScheme,
    host: String,
    port: Option<u16>,
}

fn send<Req: serde::Serialize, Res: for<'de> serde::Deserialize<'de>>(
    method: Method,
    url: Url,
    req: &Req,
) -> Result<Res, Error> {
    let client = reqwest::blocking::Client::new();
    let json = serde_json::to_string(req)
        .map_err(|e| Error::Service(format!("Failed to serialize request: {}", e)))?;

    let res = client
        .request(method, url)
        .header("Accept", "*/*")
        .header("Content-Type", "application/json")
        .body(json)
        .send()
        .map_err(|e| Error::Service(format!("Failed to send request: {}", e)))?;

    let body = res
        .text()
        .map_err(|e| Error::Service(format!("Failed to read response body: {}", e)))?;

    serde_json::from_str(&body)
        .map_err(|e| Error::Service(format!("Failed to convert response body: {}", e)))
}

impl BlockingHttpClient {
    pub fn new(scheme: HttpScheme, host: &str, port: Option<u16>) -> Self {
        Self {
            scheme,
            host: host.to_string(),
            port,
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

    pub fn convert_note_history_to_encrypted_note_history(
        &self,
        nh: NoteHistorySaved,
        username: String,
    ) -> EncryptedNoteHistory {
        let contact = self
            .get_user_from_db(UserIdentifier::Username(username))
            .expect("couldn't get contact");

        EncryptedNoteHistory {
            receiver: contact,
            encrypted: ivcnotes::cipher::EncryptedData { data: nh.data },
        }
    }

    pub fn get_user_from_db(&self, identifier: UserIdentifier) -> Result<User, String> {
        let url = self.path(Path::GetUser);
        let wrapper = IdentifierWrapper { identifier };
        let res: User =
            send(Method::GET, url, &wrapper).map_err(|e| format!("Failed to get user: {}", e))?;
        Ok(res)
    }

    pub fn get_contact(&self, identifier: UserIdentifier) -> Result<Contact<Concrete>, String> {
        let user = self.get_user_from_db(identifier).expect("cant fetch user");
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
                let smtg: SmtgWithPubkey<TE> = serde_json::from_str(pubkey_str).expect("no pubkey");
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
            step: 0,
            note: "".to_owned(),
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
    ) -> Result<String, String> {
        let nullifier_request = NullifierRequest {
            nullifier,
            state: expected_state,
        };

        let url = self.path(Path::VerifyNullifier);

        match send::<_, serde_json::Value>(Method::GET, url, &nullifier_request) {
            Ok(json) => {
                if json.get("Ok").is_some() {
                    // This is the case where we have a successful response
                    panic!("CRITICAL ERROR: Betrayal detected! The sender was flagged. Exiting for your safety.");
                } else {
                    // This is the case where we have an "Error" string
                    Ok("Nullifier verified, no betrayal detected".to_string())
                }
            }
            Err(Error::Service(e)) if e.contains("404 Not Found") => {
                Ok("Nullifier not found".to_string())
            }
            Err(_) => Err("An error occurred while verifying the nullifier".to_string()),
        }
    }

    pub fn register(&self, msg: Contact<Concrete>) -> Result<User, String> {
        let pubkey = msg.public_key.clone();
        // serialization with crate::serde
        let smtg_pubkey = SmtgWithPubkey { pubkey };
        let smtg_address = SmtgWithAddress {
            address: msg.address,
        };
        let pubkey_json = serde_json::to_string(&smtg_pubkey).unwrap();
        let address_json = serde_json::to_string(&smtg_address).unwrap();

        let create_user_schema = CreateUserSchema {
            username: msg.username.clone(),
            address: address_json,
            pubkey: pubkey_json,
            nonce: String::new(),
            messages: Vec::new(),
            notes: Vec::new(),
            has_double_spent: false,
        };

        let url = self.path(Path::CreateUser);
        let user: User = send(Method::POST, url, &create_user_schema)
            .map_err(|e| format!("Failed to create user: {}", e))?;

        Ok(user)
    }

    pub fn send_note(&self, msg: &msg::request::SendNote<Concrete>) -> Result<(), Error> {
        let address_bytes = msg.receiver.to_bytes();
        let address_json =
            serde_json::to_string(&address_bytes).expect("failed to serialize address");

        let send_and_transfer_json = NoteHistoryRequest {
            owner_username: msg.sender_username.clone(),
            recipient_username: msg.receiver_username.to_owned(),
            note_history: SaveNoteHistoryRequestSchema {
                data: msg.note_history.encrypted.data.clone(),
                address: address_json,
                sender: msg.sender_username.clone(),
            },
            message: "Transfer".to_string(),
        };

        let url = self.path(Path::CreateAndTransferNoteHistory);
        send(Method::POST, url, &send_and_transfer_json)
    }

    pub fn get_notes(
        &self,
        username: String,
    ) -> Result<Vec<(EncryptedNoteHistory, Sender)>, String> {
        let username_request = crate::schema::UsernameRequest {
            username: username.clone(),
        };
        let url = self.path(Path::GetNoteHistoryForUser);
        let note_history: Vec<NoteHistorySaved> = send(Method::GET, url, &username_request)
            .map_err(|e| format!("Failed to get notes: {}", e))?;

        let result: Vec<(EncryptedNoteHistory, Sender)> = note_history
            .into_iter()
            .map(|nh| {
                let encrypted_note_history = self.convert_note_history_to_encrypted_note_history(
                    nh.clone(),
                    username.to_owned(),
                );
                let sender = Sender {
                    username: nh.sender,
                };
                (encrypted_note_history, sender)
            })
            .collect();

        Ok(result)
    }
}
