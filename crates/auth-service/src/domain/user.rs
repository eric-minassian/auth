use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub user_id: Uuid,
    pub email: String,
    pub email_verified: bool,
    pub created_at: i64,
    pub updated_at: i64,
}
