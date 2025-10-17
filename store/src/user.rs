use crate::Store;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub public_key: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug)]
pub enum UserError {
    UserExists,
    InvalidInput(String),
    DatabaseError(String),
}

impl std::fmt::Display for UserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserError::UserExists => write!(f, "User already exists"),
            UserError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            UserError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
        }
    }
}

impl std::error::Error for UserError {}

impl Store {
    pub async fn create_user(&self, request: CreateUserRequest) -> Result<User, UserError> {
        if !request.email.contains('@') {
            return Err(UserError::InvalidInput("Invalid email format".to_string()));
        }

        if request.password.len() < 6 {
            return Err(UserError::InvalidInput(
                "Password must be at least 6 characters".to_string(),
            ));
        }

        let existing_user =
            sqlx::query!(r#"SELECT id FROM "User" WHERE email = $1"#, request.email)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        if existing_user.is_some() {
            return Err(UserError::UserExists);
        }

        let password_hash = bcrypt::hash(&request.password, bcrypt::DEFAULT_COST)
            .map_err(|e| UserError::DatabaseError(format!("Password hashing failed: {}", e)))?;

        let user_id = Uuid::new_v4();
        let created_at = Utc::now();
        let updated_at = Utc::now();

        sqlx::query!(
            r#"
            INSERT INTO "User" (id, email, password, publicKey, createdAt, updatedAt)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            user_id,
            request.email,
            password_hash,
            Option::<String>::None,
            created_at,
            updated_at
        )
        .execute(&self.pool)
        .await
        .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        Ok(User {
            id: user_id,
            email: request.email,
            public_key: None,
            created_at,
            updated_at,
        })
    }
}
