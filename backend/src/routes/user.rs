use crate::auth_middleware::AuthToken;
use actix_web::{get, post};
use actix_web::{web, HttpResponse, Result};
use bcrypt::{hash, verify};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::env;
use uuid::Uuid;
use store::mpc_key::SaveKeyRequest;
use store::mpc_store::MPCStore;

#[derive(Deserialize)]
pub struct SignUpRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct SignInRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub email: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
}

#[derive(Serialize)]
pub struct SignupResponse {
    message: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Deserialize, Serialize)]
struct Round1Resp {
    id: u16,
    pkg_hex: String,
}

#[derive(Deserialize)]
struct Round2InitResp {
    from: u16,
    packages: std::collections::HashMap<u16, String>,
}

#[derive(Deserialize, Serialize)]
struct Round2RecvReq {
    from: u16,
    pkg_hex: String,
}

#[derive(Deserialize)]
struct Round2Resp {
    id: u16,
    pubkey: String,
}

fn generate_jwt(email: &str) -> String {
    let secret = env::var("JWT_SECRET").unwrap_or("secret".to_string());

    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: email.to_owned(),
        exp: expiration,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .expect("JWT should be generated")
}

fn validate_jwt(token: &str) -> Option<String> {
    let secret = env::var("JWT_SECRET").unwrap_or("secret".to_string());

    match decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    ) {
        Ok(data) => Some(data.claims.sub),
        Err(_) => None,
    }
}

#[post("/api/v1/signup")]
pub async fn sign_up(
    pool: web::Data<PgPool>,
    req: web::Json<SignUpRequest>,
) -> Result<HttpResponse, actix_web::Error> {
    let existing = sqlx::query!("SELECT id FROM \"User\" WHERE email = $1", &req.username)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("DB error: {}", e)))?;

    if existing.is_some() {
        return Err(actix_web::error::ErrorUnauthorized("User already exists"));
    }

    let password_hash = hash(&req.password, bcrypt::DEFAULT_COST)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Hash error: {}", e)))?;

    let client = Client::new();
    let mpc_nodes = vec![
        ("http://127.0.0.1:8081", 1),
        ("http://127.0.0.1:8082", 2),
        ("http://127.0.0.1:8083", 3),
    ];

    let mut all_r1: Vec<Round1Resp> = Vec::new();
    for (url, _) in &mpc_nodes {
        let resp = client
            .post(format!("{url}/dkg-round1"))
            .send()
            .await
            .map_err(|e| {
                actix_web::error::ErrorInternalServerError(format!("MPC /dkg-round1 failed: {}", e))
            })?;

        let r1_resp: Round1Resp = resp.json().await.map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("Invalid /dkg-round1 resp: {}", e))
        })?;

        all_r1.push(r1_resp);
    }

    println!("Collected {} Round-1 packages", all_r1.len());

    let mut all_r2_responses: Vec<Round2InitResp> = Vec::new();
    for (url, _) in &mpc_nodes {
        let r2_resp = client
            .post(format!("{url}/dkg-round2-init"))
            .json(&all_r1)
            .send()
            .await
            .map_err(|e| {
                actix_web::error::ErrorInternalServerError(format!(
                    "MPC /dkg-round2-init failed on {url}: {}",
                    e
                ))
            })?;

        let r2_json: Round2InitResp = r2_resp.json().await.map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Invalid /dkg-round2-init resp from {url}: {}",
                e
            ))
        })?;

        all_r2_responses.push(r2_json);
    }

    for (url, node_id) in &mpc_nodes {
        for r2_resp in &all_r2_responses {
            if r2_resp.from != *node_id {
                for (recipient_id, pkg_hex) in &r2_resp.packages {
                    if *recipient_id == *node_id {
                        let recv_req = Round2RecvReq {
                            from: r2_resp.from,
                            pkg_hex: pkg_hex.clone(),
                        };
                        
                        let _ = client
                            .post(format!("{url}/dkg-round2-recv"))
                            .json(&recv_req)
                            .send()
                            .await;
                    }
                }
            }
        }
    }

    let mut agg_pk_str = String::new();
    for (url, _) in &mpc_nodes {
        let finalize_resp = client
            .post(format!("{url}/dkg-finalize"))
            .send()
            .await
            .map_err(|e| {
                actix_web::error::ErrorInternalServerError(format!(
                    "MPC /dkg-finalize failed on {url}: {}",
                    e
                ))
            })?;

        let finalize_json: Round2Resp = finalize_resp.json().await.map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!(
                "Invalid /dkg-finalize resp from {url}: {}",
                e
            ))
        })?;

        println!("Node {url} finalized with pubkey = {}", finalize_json.pubkey);
        agg_pk_str = finalize_json.pubkey;
    }

    let mpc1_pool = PgPool::connect("postgres://mpc:mpcpass@localhost:5433/mpc1").await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("MPC1 DB connect error: {}", e)))?;
    let mpc2_pool = PgPool::connect("postgres://mpc:mpcpass@localhost:5434/mpc2").await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("MPC2 DB connect error: {}", e)))?;
    let mpc3_pool = PgPool::connect("postgres://mpc:mpcpass@localhost:5435/mpc3").await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("MPC3 DB connect error: {}", e)))?;

    let mpc1_store = MPCStore::new(mpc1_pool);
    let mpc2_store = MPCStore::new(mpc2_pool);
    let mpc3_store = MPCStore::new(mpc3_pool);

    for (_, node_id) in &mpc_nodes {
        let key_pkg = vec![1, 2, 3, 4]; // This should be the actual key package from DKG
        let save_req = SaveKeyRequest {
            pubkey: agg_pk_str.clone(),
            user_email: req.username.clone(),
            node_id: *node_id as i16,
            key_pkg,
        };

        match node_id {
            1 => mpc1_store.save_mpc_key(save_req).await
                .map_err(|e| actix_web::error::ErrorInternalServerError(format!("MPC1 save error: {}", e)))?,
            2 => mpc2_store.save_mpc_key(save_req).await
                .map_err(|e| actix_web::error::ErrorInternalServerError(format!("MPC2 save error: {}", e)))?,
            3 => mpc3_store.save_mpc_key(save_req).await
                .map_err(|e| actix_web::error::ErrorInternalServerError(format!("MPC3 save error: {}", e)))?,
            _ => return Err(actix_web::error::ErrorInternalServerError("Invalid node ID".to_string())),
        }
    }
    
    let user_id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO \"User\" (id, email, password, createdAt, updatedAt, publicKey)
         VALUES ($1, $2, $3, NOW(), NOW(), $4)",
        user_id,
        &req.username,
        password_hash,
        agg_pk_str
    )
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(format!("DB insert error: {}", e)))?;

    Ok(HttpResponse::Ok().json(SignupResponse {
        message: "signed up successfully".to_string(),
    }))
}

#[post("/api/v1/signin")]
pub async fn sign_in(
    pool: web::Data<PgPool>,
    req: web::Json<SignInRequest>,
) -> Result<HttpResponse, actix_web::Error> {
    let row = sqlx::query!(
        "SELECT email, password FROM \"User\" WHERE email = $1",
        req.username
    )
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(format!("DB query error: {}", e)))?;

    if let Some(user) = row {
        if verify(&req.password, &user.password).unwrap_or(false) {
            let jwt = generate_jwt(&user.email);
            return Ok(HttpResponse::Ok().json(AuthResponse { token: jwt }));
        }
    }

    Err(actix_web::error::ErrorUnauthorized("Invalid credentials"))
}

#[get("/api/v1/user")]
pub async fn get_user(
    pool: web::Data<PgPool>,
    auth: AuthToken,
) -> Result<HttpResponse, actix_web::Error> {
    if let Some(email) = validate_jwt(&auth.0) {
        let row = sqlx::query!("SELECT email FROM \"User\" WHERE email = $1", email)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

        if let Some(user) = row {
            return Ok(HttpResponse::Ok().json(UserResponse { email: user.email }));
        }
    }

    Err(actix_web::error::ErrorUnauthorized("Unauthorized"))
}
