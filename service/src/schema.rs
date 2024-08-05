use mongodb::bson::{doc, Bson};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub has_double_spent: Option<bool>,
    pub nonce: Option<String>,
    pub username: Option<String>,
    pub pubkey: Option<String>,
    pub messages: Option<Vec<String>>,
    pub notes: Option<Vec<bson::oid::ObjectId>>,
    pub address: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateUserSchema {
    pub username: String,
    pub pubkey: String,
    pub nonce: String,
    pub address: String,
    pub messages: Vec<String>,
    pub notes: Vec<String>,
    pub has_double_spent: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserRequest {
    pub identifier: UserIdentifier,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum UserIdentifier {
    Username(String),
    Address(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UsernameRequest {
    pub username: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NoteSchema {
    pub(crate) asset_hash: String,
    pub(crate) owner: String,
    pub(crate) value: u64,
    pub(crate) step: u32,
    pub(crate) parent_note: String,
    pub(crate) out_index: String,
    pub(crate) blind: String,
    pub(crate) _id: Option<Bson>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SaveNoteRequestSchema {
    pub(crate) asset_hash: String,
    pub(crate) owner: String,
    pub(crate) value: u64,
    pub(crate) step: u32,
    pub(crate) parent_note: String,
    pub(crate) out_index: String,
    pub(crate) blind: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SaveNoteHistoryRequestSchema {
    pub data: Vec<u8>,
    pub address: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NoteHistorySaved {
    pub data: Vec<u8>,
    pub address: String,
    pub _id: Option<Bson>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NoteHistorySchema {
    note: NoteSchema,
    history: Vec<NoteSchema>,
    spent: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MessageSchema {
    pub recipient: String,
    pub sender: String,
    pub message: String,
    pub timestamp: i64,
    pub attachment_id: Option<Bson>,
    pub read: bool,
    pub _id: Option<Bson>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct MessageRequestSchema {
    pub recipient: String,
    pub sender: String,
    pub message: String,
    pub attachment_id: Option<Bson>,
}

// We must add a future state vector
#[derive(Debug, Deserialize, Serialize)]
pub struct NoteNullifierSchema {
    pub nullifier: String,
    pub note: String, // Note structure serialized as JSON
    pub step: i32,
    pub owner: String, // Address serialized as JSON
    pub state: String,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct NullifierRequest {
    pub nullifier: String,
    pub state: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NoteRequest {
    pub owner_pub_key: String,
    pub step: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NoteHistoryRequest {
    pub owner_username: Option<String>,
    pub recipient_username: String,
    pub note_history: SaveNoteHistoryRequestSchema,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeSchema {
    pub challenge_id: String,
    pub user_id: String,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthData {
    pub username: String,
    pub signature_hex: String,
    pub challenge_id: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct UserSingleResponse {
    pub status: &'static str,
    pub user: User,
}

#[derive(Debug, Serialize)]
pub struct MessageSingleResponse {
    pub status: &'static str,
    pub message: MessageSchema,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct NullifierResponseData {
    pub status: &'static str,
    pub nullifier: NoteNullifierSchema,
}
#[derive(Debug, Serialize)]
pub enum NullifierResponse {
    Ok(NoteNullifierSchema),
    NotFound,
    Error,
}

#[derive(Debug, Serialize)]
pub struct NoteResponse {
    pub status: &'static str,
    pub note: NoteSchema,
}

#[derive(Debug, Serialize)]
pub struct NoteHistoryResponse {
    pub status: &'static str,
    pub note_history: NoteHistorySaved,
}

#[derive(Serialize)]
pub struct IdentifierWrapper {
    pub identifier: UserIdentifier,
}

pub struct Contact<E: ivcnotes::circuit::IVC> {
    #[serde(with = "crate::ark_serde")]
    pub address: ivcnotes::Address<E::Field>,
    pub username: String,
    #[serde(with = "crate::ark_serde")]
    pub public_key: ivcnotes::PublicKey<E::TE>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SmtgWithPubkey<TE: ark_ec::twisted_edwards::TECurveConfig> {
    #[serde(with = "ivcnotes::ark_serde")]
    pub pubkey: ivcnotes::PublicKey<TE>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct SmtgWithAddress<F: ark_ff::PrimeField> {
    #[serde(with = "ivcnotes::ark_serde")]
    pub address: ivcnotes::Address<F>,
}
