pub mod blocking;

fn main() {}

// impl Service

// impl Service<ConcreteIVC> for SharedMockService {
//     fn register(
//         &self,
//         msg: &super::msg::request::Register<ConcreteIVC>,
//     ) -> Result<(), crate::Error> {
//         let sk: SigningKey<TE> = SigningKey::generate::<sha2::Sha512>(&mut OsRng).unwrap();
//         let pubkey = sk.public_key().clone();
//         // serialization with crate::serde
//         let smtg_pubkey = SmtgWithPubkey { pubkey };
//         let smtg_address = SmtgWithAddress {
//             address: msg.address,
//         };
//         let pubkey_json = serde_json::to_string(&smtg_pubkey).unwrap();
//         let address_json = serde_json::to_string(&smtg_address).unwrap();

//         let client = reqwest::blocking::Client::new();

//         let create_user_schema = crate::service_schema::CreateUserSchema {
//             username: msg.username.clone(),
//             address: address_json,
//             pubkey: pubkey_json,
//             nonce: String::new(), // You might want to generate a nonce
//             messages: Vec::new(),
//             notes: Vec::new(),
//             has_double_spent: false,
//         };

//         let json_body = serde_json::to_string(&create_user_schema)
//             .expect("Failed to serialize CreateUserSchema");

//         let _ = client
//             .post("http://167.172.25.99:80/create_user")
//             .header("Accept", "*/*")
//             .header("Content-Type", "application/json")
//             .body(json_body)
//             .send();
//         Ok(())
//     }

//     fn get_user_from_db(
//         &self,
//         identifier: UserIdentifier,
//     ) -> Result<Contact<crate::circuit::test::ConcreteIVC>, String> {
//         let client = reqwest::blocking::Client::new();
//         let wrapper = IdentifierWrapper { identifier };
//         let json_body = serde_json::to_string(&wrapper).expect("Failed to serialize to json");
//         let res = client
//             .get("http://167.172.25.99/get_user")
//             .header("Accept", "*/*")
//             .header("Content-Type", "application/json")
//             .body(json_body)
//             .send()
//             .map_err(|e| format!("Failed to send request: {}", e))?;

//         if res.status().is_success() {
//             let res_text = res
//                 .text()
//                 .map_err(|e| format!("Failed to read response body: {}", e));

//             let user: User = serde_json::from_str(&res_text.unwrap()).unwrap();
//             let address: Address<ark_bn254::Fr> = match user.address {
//                 Some(ref address_str) => {
//                     let smtg: SmtgWithAddress<ark_bn254::Fr> =
//                         serde_json::from_str(address_str).expect("no address");
//                     smtg.address
//                 }
//                 None => return Err("User address is None".into()),
//             };

//             let pubkey: PublicKey<TE> = match user.pubkey {
//                 Some(ref pubkey_str) => {
//                     println!("string of pubkey, {:#?}", pubkey_str);
//                     let smtg: SmtgWithPubkey<TE> =
//                         serde_json::from_str(pubkey_str).expect("no pubkey");
//                     smtg.pubkey
//                 }
//                 None => return Err("User pubkey is None".into()),
//             };

//             let contact = Contact {
//                 public_key: pubkey,
//                 address,
//                 username: user.username.ok_or("Username is None")?,
//             };

//             Ok(contact)
//         } else {
//             Err(format!("Request failed with status: {}", res.status()))
//         }
//     }

//     fn get_contact(
//         &self,
//         msg: &super::msg::request::GetContact<Fr>,
//     ) -> Result<super::msg::response::Contact<ConcreteIVC>, crate::Error> {
//         let mut shared = self.shared.borrow_mut(); // Note: changed to mutable borrow

//         let contact = match msg {
//             super::msg::request::GetContact::Username(username) => {
//                 println!("{:#?}, {:#?}", msg, username);
//                 shared
//                     .contacts
//                     .values()
//                     .find(|contact| contact.username == *username)
//                     .cloned()
//                     .or_else(|| {
//                         // Fetch from DB if not in shared
//                         self.get_user_from_db(crate::service_schema::UserIdentifier::Username(
//                             username.clone(),
//                         ))
//                         .ok()
//                     })
//             }
//             super::msg::request::GetContact::Address(address) => {
//                 println!("{:#?}, {:#?}", msg, address);
//                 shared.contacts.get(address).cloned().or_else(|| {
//                     let smtg_address = SmtgWithAddress { address: *address };
//                     let address_json = serde_json::to_string(&smtg_address).unwrap();
//                     self.get_user_from_db(crate::service_schema::UserIdentifier::Address(
//                         address_json,
//                     ))
//                     .ok()
//                 })
//             }
//         };

//         match contact {
//             Some(contact) => {
//                 // Add the contact to shared if it wasn't there before
//                 shared
//                     .contacts
//                     .entry(contact.address)
//                     .or_insert_with(|| contact.clone());
//                 Ok(contact)
//             }
//             None => Err(crate::Error::With("contact not found")),
//         }
//     }

//     fn send_note(
//         &self,
//         msg: &super::msg::request::Note<ConcreteIVC>,
//     ) -> Result<(), crate::Error> {
//         let client = reqwest::blocking::Client::new();
//         let smtg_address = SmtgWithAddress {
//             address: msg.receiver,
//         };
//         let address_json = serde_json::to_string(&smtg_address).unwrap();

//         let send_and_transfer_json = crate::service_schema::NoteHistoryRequest {
//             owner_username: None,
//             recipient_username: msg.username.clone(),
//             note_history: SaveNoteHistoryRequestSchema {
//                 data: msg.note_history.encrypted.data.clone(),
//                 address: address_json,
//             },
//             message: "Transfer".to_string(),
//         };

//         let json_body = serde_json::to_string(&send_and_transfer_json)
//             .expect("Failed to serialize Notehistory");

//         let res = client
//             .post("http://167.172.25.99/create_and_transfer_note_history")
//             .header("Accept", "*/*")
//             .header("Content-Type", "application/json")
//             .body(json_body)
//             .send()
//             .map_err(|e| format!("Failed to send request: {}", e));

//         println!("{:#?}", res);

//         Ok(())
//     }

//     fn get_notes(
//         &self,
//         msg: &super::msg::request::GetNotes<Fr>,
//     ) -> Result<super::msg::response::Notes<ConcreteIVC>, String> {
//         println!("GET NOTES???");
//         let client = reqwest::blocking::Client::new();

//         let username_request = crate::service_schema::UsernameRequest {
//             username: msg.username.clone(), // Assuming receiver is the username we want to fetch notes for
//         };

//         let json_body = serde_json::to_string(&username_request)
//             .expect("Failed to serialize UsernameRequest");

//         let res = client
//             .get("http://167.172.25.99/get_note_history_for_user") // Adjust the URL as needed
//             .header("Accept", "*/*")
//             .header("Content-Type", "application/json")
//             .body(json_body)
//             .send()
//             .map_err(|e| format!("Failed to send request: {}", e))
//             .expect("no client");

//         if res.status().is_success() {
//             let res_text = res
//                 .text()
//                 .map_err(|e| format!("Failed to read response body: {}", e));

//             let note_history: Vec<crate::service_schema::NoteHistorySaved> =
//                 serde_json::from_str(&res_text.unwrap()).unwrap();

//             let encrypted_note_history: Vec<EncryptedNoteHistory<ConcreteIVC>> = note_history
//                 .into_iter()
//                 .map(|nh| {
//                     self.convert_note_history_to_encrypted_note_history(
//                         nh,
//                         msg.username.clone(),
//                     )
//                 })
//                 .collect();

//             Ok(super::msg::response::Notes {
//                 notes: encrypted_note_history,
//             })
//         } else {
//             Err(format!("Request failed with status: {}", res.status()))
//         }
//     }

//     fn convert_note_history_to_encrypted_note_history(
//         &self,
//         nh: crate::service_schema::NoteHistorySaved,
//         username: String,
//     ) -> EncryptedNoteHistory<ConcreteIVC> {
//         // Parse the address string to extract sender information
//         let contact = self
//             .get_user_from_db(crate::service_schema::UserIdentifier::Username(
//                 username.clone(),
//             ))
//             .expect("couldn't get contact");
//         println!("CONVERT CONTACT {:#?}", contact);
//         EncryptedNoteHistory {
//             sender: contact,
//             encrypted: crate::cipher::EncryptedData { data: nh.data },
//         }
//     }
// }
// }
