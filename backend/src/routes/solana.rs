use actix_web::{get, post};
use actix_web::{web, Error as ActixError, HttpResponse, Result};
use bcrypt::{hash, verify};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::{collections::HashMap, env, str::FromStr, sync::Mutex};
use uuid::Uuid;

use crate::auth_middleware::AuthToken;
use crate::user::UserResponse;

use lazy_static::lazy_static;
lazy_static! {
    static ref QUOTES: Mutex<HashMap<String, serde_json::Value>> = Mutex::new(HashMap::new());
}
const JUP_QUOTE_URL: &str = "https://lite-api.jup.ag/swap/v1/quote";
const JUP_SWAP_URL: &str = "https://lite-api.jup.ag/swap/v1/swap";

#[derive(Deserialize)]
pub struct SignUpRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CommitmentsMsg {
    pub id: u16,
    pub commitments: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ShareMsg {
    pub id: u16,
    pub share: serde_json::Value, // same idea
}

#[derive(Deserialize)]
pub struct SignInRequest {
    pub username: String,
    pub password: String,
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

#[derive(Deserialize)]
pub struct QuoteRequest {
    #[serde(rename = "inputMint")]
    pub input_mint: String,
    #[serde(rename = "outputMint")]
    pub output_mint: String,
    #[serde(rename = "inAmount")]
    pub in_amount: u64,
}

#[derive(Serialize)]
pub struct QuoteResponse {
    #[serde(rename = "outAmount")]
    pub out_amount: u64,
    pub id: String,
}

#[derive(Deserialize)]
pub struct SwapRequest {
    pub id: String,
}

#[derive(Deserialize)]
pub struct SendRequest {
    pub to: String,
    pub amount: u64,
    pub mint: Option<String>,
}

#[derive(Deserialize)]
struct AggregateSignatureResponse {
    signature_hex: String,
    signature_base64: String,
    solana_signature: String,
}

fn generate_jwt(email: &str) -> String {
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "secret".to_string());
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .expect("valid ts")
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
        Err(e) => {
            eprintln!("JWT decode error: {:?}", e);
            None
        }
    }
}

fn mpc_nodes() -> (Vec<String>, Vec<u16>) {
    let nodes = vec![
        env::var("MPC_NODE_1").unwrap_or_else(|_| "http://127.0.0.1:8081".to_string()),
        env::var("MPC_NODE_2").unwrap_or_else(|_| "http://127.0.0.1:8082".to_string()),
        env::var("MPC_NODE_3").unwrap_or_else(|_| "http://127.0.0.1:8083".to_string()),
    ];
    let parties = vec![1u16, 2u16, 3u16];
    (nodes, parties)
}

#[derive(Deserialize)]
struct PubkeyResponse {
    pub pubkey: String,
}

#[post("/api/v1/signup")]
pub async fn sign_up(
    pool: web::Data<PgPool>,
    req: web::Json<SignUpRequest>,
) -> Result<HttpResponse, ActixError> {
    let client = Client::new();
    let (nodes, _) = mpc_nodes();

    let mut all_r1: Vec<serde_json::Value> = Vec::new();
    for url in &nodes {
        let resp = client
            .post(format!("{url}/dkg-round1"))
            .send()
            .await
            .map_err(|e| actix_web::error::ErrorInternalServerError(format!("r1 error: {e}")))?;
        let text = resp.text().await.unwrap_or_default();
        let r1: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("bad r1 json: {e}, body={text}"))
        })?;
        all_r1.push(r1);
    }

    let mut all_r2: Vec<serde_json::Value> = Vec::new();
    for (i, url) in nodes.iter().enumerate() {
        let peers: Vec<_> = all_r1
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, v)| v.clone())
            .collect();

        let resp = client
            .post(format!("{url}/dkg-round2-init"))
            .json(&peers)
            .send()
            .await
            .map_err(|e| {
                actix_web::error::ErrorInternalServerError(format!("r2 init error: {e}"))
            })?;
        let text = resp.text().await.unwrap_or_default();
        let r2: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("bad r2 json: {e}, body={text}"))
        })?;
        all_r2.push(r2);
    }

    for (from_idx, r2) in all_r2.iter().enumerate() {
        let from_id = (from_idx + 1) as u16;
        if let Some(pkgs) = r2["packages"].as_object() {
            for (to_str, pkg_hex) in pkgs {
                let to_id: usize = to_str.parse().unwrap();
                let url = &nodes[to_id - 1];
                let body = serde_json::json!({ "from": from_id, "pkg_hex": pkg_hex });
                client
                    .post(format!("{url}/dkg-round2-recv"))
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| {
                        actix_web::error::ErrorInternalServerError(format!("r2 recv error: {e}"))
                    })?;
            }
        }
    }

    // Finalize DKG on all nodes    t t
    for url in &nodes {
        let finalize_resp = client
            .post(format!("{url}/dkg-finalize"))
            .send()
            .await
            .map_err(|e| {
                actix_web::error::ErrorInternalServerError(format!("finalize error: {e}"))
            })?;

        if !finalize_resp.status().is_success() {
            let error_text = finalize_resp.text().await.unwrap_or_default();
            return Err(actix_web::error::ErrorInternalServerError(format!(
                "DKG finalize failed on {}: {}",
                url, error_text
            )));
        }
    }

    // Get the aggregated public key
    let pubkey_resp = client
        .get(format!("{}/pubkey", &nodes[0]))
        .send()
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("pubkey error: {e}")))?;

    let text = pubkey_resp.text().await.unwrap_or_default();
    println!("DEBUG /pubkey body = {}", text);

    let pk_obj: PubkeyResponse = serde_json::from_str(&text).map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("pubkey parse error: {e}, body={text}"))
    })?;
    let agg_pubkey = pk_obj.pubkey;

    // DKG state is now automatically saved by each MPC node during dkg_finalize
    // No need for external save calls - this eliminates timing issues
    println!("DKG completed successfully - state automatically saved by MPC nodes");

    let password_hash = hash(&req.password, bcrypt::DEFAULT_COST)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("hash error: {e}")))?;
    let user_id = Uuid::new_v4();

    sqlx::query!(
        "INSERT INTO \"User\" (id, email, password, createdat, updatedat, publickey)
         VALUES ($1, $2, $3, NOW(), NOW(), $4)",
        user_id,
        &req.username,
        password_hash,
        agg_pubkey
    )
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(format!("DB insert error: {e}")))?;

    // Note: DKG state is now automatically saved during dkg_finalize with placeholder email
    // TODO: In production, add an email-only update endpoint to replace placeholder with real email
    println!("DKG state auto-saved with placeholder email - consider adding email update endpoint for production");

    Ok(HttpResponse::Ok().json(SignupResponse {
        message: "signed up successfully".into(),
    }))
}

#[post("/api/v1/signin")]
pub async fn sign_in(
    pool: web::Data<PgPool>,
    req: web::Json<SignInRequest>,
) -> Result<HttpResponse, ActixError> {
    // Fetch user by email
    let row = sqlx::query!(
        r#"
        SELECT id, email, password
        FROM "User"
        WHERE email = $1
        "#,
        req.username
    )
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(format!("DB query error: {e}")))?;

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
) -> Result<HttpResponse, ActixError> {
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

#[post("/api/v1/quote")]
pub async fn quote(req: web::Json<QuoteRequest>) -> Result<HttpResponse, ActixError> {
    if req.in_amount == 0 {
        return Ok(HttpResponse::BadRequest().body("Invalid input amount"));
    }
    let client = Client::new();
    let url = format!(
        "{JUP_QUOTE_URL}?inputMint={}&outputMint={}&amount={}&slippageBps=50",
        req.input_mint, req.output_mint, req.in_amount
    );
    let res = client.get(&url).send().await.map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Jupiter quote error: {e}"))
    })?;
    if !res.status().is_success() {
        return Ok(HttpResponse::BadRequest().body("Invalid input or insufficient balance"));
    }
    let data: serde_json::Value = res.json().await.map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Jupiter parse error: {e}"))
    })?;
    let out_amount: u64 = data["otherAmountThreshold"]
        .as_str()
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    if out_amount == 0 {
        return Ok(HttpResponse::BadRequest().body("Invalid quote from Jupiter"));
    }
    let id = Uuid::new_v4().to_string();
    QUOTES.lock().unwrap().insert(id.clone(), data);
    Ok(HttpResponse::Ok().json(QuoteResponse {
        out_amount: out_amount,
        id,
    }))
}

use base64;
use bincode;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::transaction::VersionedTransaction;

#[post("/api/v1/swap")]
pub async fn swap(
    pool: web::Data<PgPool>,
    auth: AuthToken,
    req: web::Json<SwapRequest>,
) -> Result<HttpResponse, ActixError> {
    if req.id.is_empty() {
        return Ok(HttpResponse::BadRequest().body("Invalid input"));
    }

    // Get logged-in user email from JWT
    let email =
        validate_jwt(&auth.0).ok_or_else(|| actix_web::error::ErrorUnauthorized("Unauthorized"))?;

    // Fetch user's aggregate pubkey from DB
    let row = sqlx::query!(r#"SELECT publickey FROM "User" WHERE email = $1"#, email)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("DB fetch user pubkey error: {e}"))
        })?;
    let user_pubkey = row.publickey;

    // Lookup cached quote
    let stored = { QUOTES.lock().unwrap().get(&req.id).cloned() };
    if stored.is_none() {
        return Ok(HttpResponse::BadRequest().body("Quote not found or expired"));
    }

    // Ask Jupiter for swap tx
    let body = serde_json::json!({
        "quoteResponse": stored.unwrap(),
        "userPublicKey": user_pubkey,
        "wrapUnwrapSOL": true,
        "useSharedAccounts": false,
        "asLegacyTransaction": true,
        "restrictIntermediateTokens": true
    });

    println!("Requesting Jupiter swap with body={}", body);

    let client = Client::new();
    let res = client
        .post(JUP_SWAP_URL)
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("Jupiter swap error: {e}"))
        })?;

    let status = res.status();
    let text = res.text().await.unwrap_or_default();
    println!("Jupiter raw response: status={}, body={}", status, text);

    if !status.is_success() {
        return Ok(HttpResponse::BadRequest().body("Swap request failed"));
    }

    let data: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Swap parse error: {e}, body={text}"))
    })?;

    let tx_b64 = data["swapTransaction"].as_str().ok_or_else(|| {
        actix_web::error::ErrorInternalServerError("No swapTransaction in response")
    })?;

    // Decode Jupiter tx into VersionedTransaction
    let tx_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, tx_b64)
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("base64 decode error: {e}"))
        })?;
    let mut tx: VersionedTransaction = bincode::deserialize(&tx_bytes).map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("tx deserialize error: {e}"))
    })?;

    // Get fresh blockhash to avoid "Blockhash not found" error
    let rpc_url =
        env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
    let rpc = RpcClient::new(rpc_url);
    
    let latest_blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to get latest blockhash: {e}")))?;
    
    // Update transaction with fresh blockhash
    match &mut tx.message {
        solana_sdk::message::VersionedMessage::Legacy(ref mut msg) => {
            msg.recent_blockhash = latest_blockhash;
        }
        solana_sdk::message::VersionedMessage::V0(ref mut msg) => {
            msg.recent_blockhash = latest_blockhash;
        }
    }

    // Ensure DKG state is loaded before signing
    ensure_dkg_loaded(&user_pubkey).await.map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Failed to load DKG state: {e}"))
    })?;

    // MPC sign message with updated blockhash
    let msg_hex = hex::encode(tx.message.serialize());
    println!(
        "Message hex (first 64 chars): {}",
        &msg_hex[..64.min(msg_hex.len())]
    );

    let sig = mpc_sign_message(msg_hex)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("MPC sign failed: {e}")))?;
    tx.signatures = vec![sig]; // Replace Jupiter's placeholder

    // Send to Solana RPC with retry mechanism
    let mut retries = 3;
    let mut signature = None;
    let mut last_error = String::new();
    
    while retries > 0 {
        match rpc
            .send_and_confirm_transaction(&tx)
            .await
        {
            Ok(sig) => {
                signature = Some(sig);
                break;
            }
            Err(e) => {
                last_error = e.to_string();
                println!("Transaction failed (retries left: {}): {}", retries - 1, e);
                retries -= 1;
                if retries > 0 {
                    // Wait a bit before retrying
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                    
                    // Get fresh blockhash for retry
                    let new_blockhash = rpc
                        .get_latest_blockhash()
                        .await
                        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to get fresh blockhash for retry: {e}")))?;
                    
                    // Update transaction with new blockhash
                    match &mut tx.message {
                        solana_sdk::message::VersionedMessage::Legacy(ref mut msg) => {
                            msg.recent_blockhash = new_blockhash;
                        }
                        solana_sdk::message::VersionedMessage::V0(ref mut msg) => {
                            msg.recent_blockhash = new_blockhash;
                        }
                    }
                    
                    // Re-sign with new blockhash
                    let msg_hex = hex::encode(tx.message.serialize());
                    let sig = mpc_sign_message(msg_hex)
                        .await
                        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("MPC re-sign failed: {e}")))?;
                    tx.signatures = vec![sig];
                }
            }
        }
    }
    
    let signature = signature.ok_or_else(|| {
        actix_web::error::ErrorInternalServerError(format!("Transaction failed after all retries. Last error: {}", last_error))
    })?;

    println!("Swap sent successfully. Signature={}", signature);

    #[derive(Serialize)]
    struct SwapResponseSigned {
        message: String,
        signature: String,
    }

    Ok(HttpResponse::Ok().json(SwapResponseSigned {
        message: "Swap executed".into(),
        signature: signature.to_string(),
    }))
}

use solana_sdk::{
    pubkey::Pubkey, signature::Signature, system_instruction, transaction::Transaction,
};

#[derive(Serialize)]
struct SignRound2Request {
    message: String,
    message_format: String,
    commitments: Vec<CommitmentsMsg>,
}

#[post("/api/v1/send")]
pub async fn send(
    pool: web::Data<PgPool>,
    auth: AuthToken,
    req: web::Json<SendRequest>,
) -> Result<HttpResponse, ActixError> {
    if req.to.is_empty() || req.amount == 0 {
        return Ok(HttpResponse::BadRequest().body("Invalid input"));
    }

    let email =
        validate_jwt(&auth.0).ok_or_else(|| actix_web::error::ErrorUnauthorized("Unauthorized"))?;
    let row = sqlx::query!("SELECT publickey FROM \"User\" WHERE email = $1", email)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("DB error: {e}")))?;
    let from_pubkey = Pubkey::from_str(&row.publickey)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Bad stored publicKey"))?;

    let rpc_url =
        env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
    let rpc = RpcClient::new(rpc_url);

    let blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Blockhash error: {e}")))?;

    let to_pubkey = Pubkey::from_str(&req.to)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Invalid recipient pubkey"))?;

    let instructions = if let Some(_mint) = &req.mint {
        // For now, return an error for token transfers as they require more complex setup
        return Ok(HttpResponse::BadRequest().body("Token transfers not yet implemented"));
    } else {
        // SOL transfer
        vec![system_instruction::transfer(
            &from_pubkey,
            &to_pubkey,
            req.amount,
        )]
    };

    let mut tx = Transaction::new_with_payer(&instructions, Some(&from_pubkey));
    tx.message.recent_blockhash = blockhash;

    // Ensure DKG state is loaded before signing
    ensure_dkg_loaded(&row.publickey).await.map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Failed to load DKG state: {e}"))
    })?;

    let msg_hex = hex::encode(tx.message_data());
    let sig = mpc_sign_message(msg_hex)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("MPC sign failed: {e}")))?;
    tx.signatures = vec![sig];

    let signature = rpc.send_and_confirm_transaction(&tx).await.map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Transaction error: {e}"))
    })?;

    #[derive(Serialize)]
    struct SendResponse {
        message: String,
        signature: String,
    }

    Ok(HttpResponse::Ok().json(SendResponse {
        message: "Transaction sent".into(),
        signature: signature.to_string(),
    }))
}

async fn ensure_dkg_loaded(user_pubkey: &str) -> Result<(), String> {
    let client = reqwest::Client::new();
    let (nodes, _) = mpc_nodes();

    for url in &nodes {
        let load_resp = client
            .post(format!("{url}/load-dkg"))
            .json(&serde_json::json!({
                "pubkey": user_pubkey
            }))
            .send()
            .await
            .map_err(|e| format!("Failed to load DKG state from {}: {}", url, e))?;

        let load_result: serde_json::Value = load_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse load response from {}: {}", url, e))?;

        if load_result["status"] == "not_found" {
            return Err(format!(
                "DKG state not found for pubkey {} on node {}",
                user_pubkey, url
            ));
        }

        println!("Loaded DKG state from {}: {:?}", url, load_result);
    }

    Ok(())
}

pub async fn mpc_sign_message(msg_hex: String) -> Result<Signature, String> {
    let client = reqwest::Client::new();
    let (nodes, _) = mpc_nodes();

    let mut commitments: Vec<CommitmentsMsg> = Vec::new();
    for url in &nodes {
        let resp = client
            .post(format!("{url}/sign-round1"))
            .json(&serde_json::json!({
                "message": msg_hex,
                "message_format": "hex"
            }))
            .send()
            .await
            .map_err(|e| format!("step1 error on {url}: {e}"))?;

        let status = resp.status();
        let text = resp.text().await.unwrap_or_else(|_| "<no body>".into());
        println!("DEBUG Step1 {} => status: {}, body: {}", url, status, text);

        if !status.is_success() {
            return Err(format!(
                "step1 non-200 on {url} (status {status}, body {text})"
            ));
        }

        let s: CommitmentsMsg = serde_json::from_str(&text)
            .map_err(|e| format!("step1 bad json on {url}: {e}, body={text}"))?;
        commitments.push(s);
    }

    let mut shares: Vec<ShareMsg> = Vec::new();
    for url in &nodes {
        let resp = client
            .post(format!("{url}/sign-round2"))
            .json(&serde_json::json!({
                "message": msg_hex,
                "message_format": "hex",
                "commitments": commitments
            }))
            .send()
            .await
            .map_err(|e| format!("step2 error on {url}: {e}"))?;

        let status = resp.status();
        let text = resp.text().await.unwrap_or_else(|_| "<no body>".into());
        println!("DEBUG Step2 {} => status: {}, body: {}", url, status, text);

        if !status.is_success() {
            return Err(format!(
                "step2 non-200 on {url} (status {status}, body {text})"
            ));
        }

        let s2: ShareMsg = serde_json::from_str(&text)
            .map_err(|e| format!("step2 bad json on {url}: {e}, body={text}"))?;
        shares.push(s2);
    }

    let resp = client
        .post(format!("{}/aggregate-signatures", &nodes[0]))
        .json(&serde_json::json!({
            "message": msg_hex,
            "message_format": "hex",
            "commitments": commitments,
            "shares": shares
        }))
        .send()
        .await
        .map_err(|e| format!("aggregate error: {e}"))?;

    let status = resp.status();
    let text = resp.text().await.unwrap_or_else(|_| "<no body>".into());
    println!("DEBUG Aggregate => status: {}, body: {}", status, text);

    if !status.is_success() {
        return Err(format!("aggregate non-200 (status {status}, body {text})"));
    }

    let agg: AggregateSignatureResponse =
        serde_json::from_str(&text).map_err(|e| format!("aggregate bad json: {e}, body={text}"))?;

    Signature::from_str(&agg.solana_signature)
        .map_err(|_| format!("invalid base58 signature: {}", agg.solana_signature))
}

#[derive(Serialize)]
pub struct SolBalanceResponse {
    pub balance: u64,
}

#[derive(Serialize)]
pub struct TokenBalance {
    pub balance: u64,
    #[serde(rename = "tokenMint")]
    pub token_mint: String,
    pub symbol: String,
    pub decimals: u8,
}

#[derive(Serialize)]
pub struct TokenBalancesResponse {
    pub balances: Vec<TokenBalance>,
}

#[get("/api/v1/balance/sol")]
pub async fn get_sol_balance(
    pool: web::Data<PgPool>,
    auth: AuthToken,
) -> Result<HttpResponse, ActixError> {
    let email =
        validate_jwt(&auth.0).ok_or_else(|| actix_web::error::ErrorUnauthorized("Unauthorized"))?;

    let row = sqlx::query!("SELECT publickey FROM \"User\" WHERE email = $1", email)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("DB fetch user pubkey error: {e}"))
        })?;

    let user_pubkey = Pubkey::from_str(&row.publickey)
        .map_err(|_| actix_web::error::ErrorInternalServerError("Invalid stored publicKey"))?;

    let rpc_url =
        env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());
    let rpc = RpcClient::new(rpc_url);

    let balance = rpc.get_balance(&user_pubkey).await.map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Failed to get balance: {e}"))
    })?;

    Ok(HttpResponse::Ok().json(SolBalanceResponse { balance }))
}

#[get("/api/v1/balance/tokens")]
pub async fn get_token_balances(
    pool: web::Data<PgPool>,
    auth: AuthToken,
) -> Result<HttpResponse, ActixError> {
    let email =
        validate_jwt(&auth.0).ok_or_else(|| actix_web::error::ErrorUnauthorized("Unauthorized"))?;

    // Get user's public key from database
    let user_row = sqlx::query!("SELECT publickey FROM \"User\" WHERE email = $1", email)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("DB fetch user pubkey error: {e}"))
        })?;

    let user_pubkey = user_row.publickey;

    // Fetch token balances from database (populated by indexer)
    let balance_rows = sqlx::query!(
        r#"
        SELECT
            b.amount as balance,
            a.mintAddress as token_mint,
            a.symbol,
            a.decimals
        FROM "Balance" b
        JOIN "User" u ON b.userId = u.id
        JOIN "Asset" a ON b.assetId = a.id
        WHERE u.publickey = $1
        ORDER BY b.amount DESC
        "#,
        user_pubkey
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("DB fetch token balances error: {e}"))
    })?;

    // Convert database rows to response format
    let mut balances = Vec::new();
    for row in balance_rows {
        balances.push(TokenBalance {
            balance: row.balance as u64,
            token_mint: row.token_mint,
            symbol: row.symbol,
            decimals: row.decimals as u8,
        });
    }

    Ok(HttpResponse::Ok().json(TokenBalancesResponse { balances }))
}
