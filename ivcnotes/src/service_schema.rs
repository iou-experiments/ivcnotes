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
    pub notes: Option<Vec<String>>,
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
pub struct NoteHistory {
    pub(crate) asset: String,
    pub(crate) steps: Vec<String>,
    pub(crate) current_note: SaveNoteRequestSchema,
    pub(crate) sibling: String,
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
    pub attachment_id: String,
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
    pub owner_username: String,
    pub recipient_username: String,
    pub note_history: NoteHistory,
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
