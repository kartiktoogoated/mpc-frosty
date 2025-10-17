use crate::mpc_store::MPCStore;
use chrono::{DateTime, Utc};
use sqlx::Row;

#[derive(Debug, Clone)]
pub struct MPCKey {
    pub pubkey: String,
    pub user_email: String,
    pub node_id: i16,
    pub key_pkg: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct SaveKeyRequest {
    pub pubkey: String,
    pub user_email: String,
    pub node_id: i16,
    pub key_pkg: Vec<u8>,
}

#[derive(Debug)]
pub enum MPCKeyError {
    DatabaseError(String),
    NotFound,
}

impl std::fmt::Display for MPCKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MPCKeyError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            MPCKeyError::NotFound => write!(f, "MPC key not found"),
        }
    }
}
impl std::error::Error for MPCKeyError {}

impl MPCStore {
    pub async fn save_mpc_key(&self, req: SaveKeyRequest) -> Result<(), MPCKeyError> {
        sqlx::query(
            r#"
            INSERT INTO "MPCKeys" (pubkey, user_email, node_id, key_pkg, created_at)
            VALUES ($1, $2, $3, $4, NOW())
            ON CONFLICT (pubkey, node_id)
            DO UPDATE SET key_pkg = EXCLUDED.key_pkg, created_at = NOW()
            "#,
        )
        .bind(&req.pubkey)
        .bind(&req.user_email)
        .bind(req.node_id)
        .bind(&req.key_pkg)
        .execute(&self.pool)
        .await
        .map_err(|e| MPCKeyError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_mpc_key(&self, pubkey: &str, node_id: i16) -> Result<MPCKey, MPCKeyError> {
        let row = sqlx::query(
            r#"
            SELECT pubkey, user_email, node_id, key_pkg, created_at
            FROM "MPCKeys"
            WHERE pubkey = $1 AND node_id = $2
            "#,
        )
        .bind(pubkey)
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| MPCKeyError::DatabaseError(e.to_string()))?;

        if let Some(r) = row {
            Ok(MPCKey {
                pubkey: r.get::<String, _>("pubkey"),
                user_email: r.get::<String, _>("user_email"),
                node_id: r.get::<i16, _>("node_id"),
                key_pkg: r.get::<Vec<u8>, _>("key_pkg"),
                created_at: r.get::<DateTime<Utc>, _>("created_at"),
            })
        } else {
            Err(MPCKeyError::NotFound)
        }
    }
}
