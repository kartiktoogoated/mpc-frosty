#![allow(non_snake_case)]

use actix_web::{get, post, web, App, HttpServer, Responder};
use frost_ed25519::Ed25519Sha512;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::sync::Mutex;
use tss::{dkg_party_init, dkg_round1, DkgRound1, FrostParty, ThresholdParams};

use ed25519_dalek::VerifyingKey as DalekPubkey;
use frost::{keys::dkg, round1, round2, Signature, SigningPackage};
use frost_core::Identifier;
use frost_ed25519 as frost;
use solana_sdk::pubkey::Pubkey;

mod error {
    use actix_web::{HttpResponse, ResponseError};
    use std::fmt::{Display, Formatter, Result as FmtResult};

    #[derive(Debug)]
    pub struct Error(pub String);

    impl Display for Error {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            write!(f, "{}", self.0)
        }
    }

    impl ResponseError for Error {
        fn error_response(&self) -> HttpResponse {
            HttpResponse::BadRequest().body(self.0.clone())
        }
    }

    impl From<&str> for Error {
        fn from(s: &str) -> Self {
            Self(s.to_string())
        }
    }

    impl From<String> for Error {
        fn from(s: String) -> Self {
            Self(s)
        }
    }
}
use error::Error;

mod tss;

#[derive(Clone)]
pub struct MPCStore {
    pool: PgPool,
}

impl MPCStore {
    pub async fn load_key_pkg(
        &self,
        pubkey_str: &str,
        node_id: i16,
    ) -> Result<Option<Vec<u8>>, Error> {
        let row =
            sqlx::query(r#"SELECT key_pkg FROM "MPCKeys" WHERE pubkey = $1 AND node_id = $2"#)
                .bind(pubkey_str)
                .bind(node_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| Error(format!("DB load_key_pkg error: {e}")))?;

        Ok(row.map(|r| r.get::<Vec<u8>, _>("key_pkg")))
    }

    pub async fn save_dkg_state(
        &self,
        pubkey_str: &str,
        user_email: &str,
        node_id: i16,
        key_package: &frost::keys::KeyPackage,
        pubkey_package: &frost::keys::PublicKeyPackage,
    ) -> Result<(), Error> {
        println!(
            "DEBUG save_dkg_state: About to serialize key_package for node {}",
            node_id
        );

        let key_pkg_bytes = key_package
            .serialize()
            .map_err(|e| Error(format!("Failed to serialize key package: {e:?}")))?;
        let pubkey_pkg_bytes = pubkey_package
            .serialize()
            .map_err(|e| Error(format!("Failed to serialize pubkey package: {e:?}")))?;

        println!(
            "DEBUG save_dkg_state: key_pkg_bytes.len()={}, pubkey_pkg_bytes.len()={}",
            key_pkg_bytes.len(),
            pubkey_pkg_bytes.len()
        );

        sqlx::query(
            r#"
            INSERT INTO "MPCKeys" (pubkey, user_email, node_id, key_pkg, pubkey_pkg, created_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (pubkey, node_id)
            DO UPDATE SET
                key_pkg = EXCLUDED.key_pkg,
                pubkey_pkg = EXCLUDED.pubkey_pkg,
                user_email = EXCLUDED.user_email,
                created_at = NOW()
            "#,
        )
        .bind(pubkey_str)
        .bind(user_email)
        .bind(node_id)
        .bind(key_pkg_bytes)
        .bind(pubkey_pkg_bytes)
        .execute(&self.pool)
        .await
        .map_err(|e| Error(format!("DB save_dkg_state error: {e}")))?;

        println!(
            "DEBUG save_dkg_state: Successfully saved to DB for node {}",
            node_id
        );
        Ok(())
    }

    pub async fn load_dkg_packages(
        &self,
        pubkey_str: &str,
        node_id: i16,
    ) -> Result<
        Option<(
            frost::keys::KeyPackage,
            Option<frost::keys::PublicKeyPackage>,
        )>,
        Error,
    > {
        let row = sqlx::query(
            r#"SELECT key_pkg, pubkey_pkg FROM "MPCKeys" WHERE pubkey = $1 AND node_id = $2"#,
        )
        .bind(pubkey_str)
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error(format!("DB load_dkg_packages error: {e}")))?;

        if let Some(r) = row {
            let key_pkg_bytes: Vec<u8> = r.get("key_pkg");
            let key_package = frost::keys::KeyPackage::deserialize(&key_pkg_bytes)
                .map_err(|e| Error(format!("Failed to deserialize key package: {e:?}")))?;

            let pubkey_package =
                match r.try_get::<Vec<u8>, _>("pubkey_pkg") {
                    Ok(bytes) => Some(frost::keys::PublicKeyPackage::deserialize(&bytes).map_err(
                        |e| Error(format!("Failed to deserialize pubkey package: {e:?}")),
                    )?),
                    Err(_) => None,
                };

            Ok(Some((key_package, pubkey_package)))
        } else {
            Ok(None)
        }
    }
}

#[derive(Clone)]
struct AppState {
    params: ThresholdParams,
    party: Option<FrostParty>,
    round1: Option<DkgRound1>,
    pubkey_pkg: Option<frost::keys::PublicKeyPackage>,
    key_pkg: Option<frost::keys::KeyPackage>,
    nonces_by_key: HashMap<String, round1::SigningNonces>,
    commits_by_key: HashMap<String, round1::SigningCommitments>,
    sp_by_key: HashMap<String, SigningPackage>,
    shares_by_key: HashMap<String, BTreeMap<Identifier<Ed25519Sha512>, round2::SignatureShare>>,
    round2_pkgs: HashMap<
        Identifier<Ed25519Sha512>,
        BTreeMap<Identifier<Ed25519Sha512>, dkg::round2::Package>,
    >,
    all_r1: BTreeMap<Identifier<Ed25519Sha512>, dkg::round1::Package>,
    mpc_store: MPCStore,
}

#[derive(Serialize, Deserialize, Clone)]
struct Round1Resp {
    id: u16,
    pkg_hex: String,
}

impl Round1Resp {
    fn from_pkg(id: u16, pkg: &dkg::round1::Package) -> Self {
        let bytes = pkg.serialize().expect("pkg serialize");
        Self {
            id,
            pkg_hex: hex::encode(bytes),
        }
    }

    fn to_pkg(&self) -> Result<dkg::round1::Package, Error> {
        let bytes = hex::decode(&self.pkg_hex).map_err(|e| Error(format!("hex decode: {e}")))?;
        Ok(dkg::round1::Package::deserialize(&bytes)
            .map_err(|e| Error(format!("pkg deserialize: {e:?}")))?)
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct Round2Resp {
    id: u16,
    pubkey: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct SignRound1Req {
    message: String,
    message_format: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct CommitmentsMsg {
    id: u16,
    commitments: round1::SigningCommitments,
}

#[derive(Serialize, Deserialize, Clone)]
struct SignBuildReq {
    message: String,
    message_format: Option<String>,
    commitments: Vec<CommitmentsMsg>,
}

#[derive(Serialize, Deserialize, Clone)]
struct SignBuildResp {
    message_key: String,
    signer_ids: Vec<u16>,
}

#[derive(Serialize, Deserialize, Clone)]
struct SignRound2Req {
    message: String,
    message_format: Option<String>,
    commitments: Vec<CommitmentsMsg>,
}

#[derive(Serialize, Deserialize, Clone)]
struct ShareMsg {
    id: u16,
    share: round2::SignatureShare,
}

#[derive(Serialize, Deserialize, Clone)]
struct AggregateReq {
    message: String,
    message_format: Option<String>,
    commitments: Vec<CommitmentsMsg>,
    shares: Vec<ShareMsg>,
}

#[derive(Serialize, Deserialize, Clone)]
struct AggregateResp {
    signature_hex: String,
    signature_base64: String,
    solana_signature: String,
}

fn u16_from_id(id: &Identifier<Ed25519Sha512>) -> u16 {
    id.serialize()[0] as u16
}

fn decode_message(s: &str, fmt: Option<&str>) -> Result<Vec<u8>, Error> {
    match fmt.unwrap_or("utf8") {
        "hex" => Ok(hex::decode(s).map_err(|e| Error(format!("hex decode: {e}")))?),
        "base64" => {
            use base64::Engine;
            Ok(base64::engine::general_purpose::STANDARD
                .decode(s)
                .map_err(|e| Error(format!("base64 decode: {e}")))?)
        }
        "utf8" => Ok(s.as_bytes().to_vec()),
        other => Err(Error(format!("unsupported message_format: {other}"))),
    }
}

fn msg_key(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

#[post("/dkg-round1")]
async fn dkg_round1_route(state: web::Data<Mutex<AppState>>) -> Result<impl Responder, Error> {
    let mut st = state.lock().unwrap();
    let pid: u16 = env::var("PARTY_ID").unwrap().parse().unwrap();

    let mut party = dkg_party_init(pid, st.params)?;
    let r1 = dkg_round1(&mut party)?;

    st.party = Some(party.clone());
    st.round1 = Some(r1.clone());

    Ok(web::Json(Round1Resp::from_pkg(pid, &r1.pkg)))
}

#[derive(Serialize, Deserialize, Clone)]
struct Round2InitResp {
    from: u16,
    packages: HashMap<u16, String>, // recipient_id -> hex(pkg)
}

#[derive(Serialize, Deserialize, Clone)]
struct Round2RecvReq {
    from: u16,
    pkg_hex: String,
}

#[post("/dkg-round2-recv")]
async fn dkg_round2_recv(
    state: web::Data<Mutex<AppState>>,
    req: web::Json<Round2RecvReq>,
) -> Result<impl Responder, Error> {
    let mut st = state.lock().unwrap();
    let party = st.party.clone().ok_or("party not init")?;
    let my_id = party.id;

    let bytes = hex::decode(&req.pkg_hex).map_err(|e| Error(format!("hex decode: {e}")))?;
    let pkg = dkg::round2::Package::deserialize(&bytes)
        .map_err(|e| Error(format!("pkg deser: {e:?}")))?;

    let sender_id: Identifier<Ed25519Sha512> = req
        .from
        .try_into()
        .map_err(|_| Error("bad sender id".into()))?;

    st.round2_pkgs
        .entry(my_id)
        .or_default()
        .insert(sender_id, pkg);

    let stored = st.round2_pkgs.get(&my_id).unwrap();
    println!(
        "Node {} stored round2 pkg from {} (now have {} pkgs: {:?})",
        u16_from_id(&my_id),
        req.from,
        stored.len(),
        stored.keys().map(|id| u16_from_id(id)).collect::<Vec<_>>()
    );

    Ok("ok".to_string())
}

#[post("/dkg-round2-init")]
async fn dkg_round2_init(
    state: web::Data<Mutex<AppState>>,
    req: web::Json<Vec<Round1Resp>>,
) -> Result<impl Responder, Error> {
    let mut st = state.lock().unwrap();
    let mut party = st.party.clone().ok_or("party not init")?;
    let my_id = party.id;

    let mut peer_r1: BTreeMap<Identifier<Ed25519Sha512>, dkg::round1::Package> = BTreeMap::new();
    for r in req.iter() {
        let rid: Identifier<Ed25519Sha512> =
            r.id.try_into()
                .map_err(|_| Error(format!("bad id {}", r.id)))?;
        if rid == my_id {
            continue;
        }
        peer_r1.insert(rid, r.to_pkg()?);
    }

    println!(
        "Node {} received {} round1 pkgs",
        u16_from_id(&my_id),
        peer_r1.len()
    );
    for (id, _) in &peer_r1 {
        println!(" -> from {:?}", u16_from_id(id));
    }

    if peer_r1.len() != (party.params.n as usize - 1) {
        return Err(Error(format!(
            "expected {} round1 pkgs, got {}",
            party.params.n - 1,
            peer_r1.len()
        )));
    }

    let sec1 = party.take_round1_secret().ok_or("missing round1 secret")?;
    let (sec2, per_recipient) =
        dkg::part2(sec1, &peer_r1).map_err(|e| Error(format!("dkg part2: {e:?}")))?;

    party.set_round2_secret(sec2);
    st.party = Some(party.clone());

    for (id, pkg) in &peer_r1 {
        st.all_r1.insert(*id, pkg.clone());
    }
    if let Some(my_r1) = st.round1.clone() {
        st.all_r1.insert(my_r1.id, my_r1.pkg);
    }

    for (recv, pkg) in &per_recipient {
        st.round2_pkgs
            .entry(my_id)
            .or_default()
            .insert(*recv, pkg.clone());

        println!(
            "Node {} generated round2 pkg for {} (stored in my bucket)",
            u16_from_id(&my_id),
            u16_from_id(recv)
        );
    }

    let mut map = HashMap::new();
    for (recv, pkg) in per_recipient {
        let bytes = pkg
            .serialize()
            .map_err(|e| Error(format!("ser r2: {e:?}")))?;
        map.insert(u16_from_id(&recv), hex::encode(bytes));
    }

    Ok(web::Json(Round2InitResp {
        from: u16_from_id(&my_id),
        packages: map,
    }))
}

#[derive(Serialize, Deserialize)]
struct SaveDkgRequest {
    user_email: String,
}

#[post("/dkg-finalize")]
async fn dkg_finalize(state: web::Data<Mutex<AppState>>) -> Result<impl Responder, Error> {
    let mut st = state.lock().unwrap();
    let mut party = st.party.clone().ok_or("party not init")?;

    let sec2 = party.take_round2_secret().ok_or("missing round2 secret")?;

    println!(
        "Node {} finalize: all_r1 has {} entries: {:?}",
        u16_from_id(&party.id),
        st.all_r1.len(),
        st.all_r1
            .keys()
            .map(|id| u16_from_id(id))
            .collect::<Vec<_>>()
    );

    let mut r1_pkgs: BTreeMap<Identifier<Ed25519Sha512>, dkg::round1::Package> = st.all_r1.clone();
    r1_pkgs.remove(&party.id);

    if r1_pkgs.len() != (party.params.n as usize - 1) {
        return Err(Error(format!(
            "expected {} peer round1 pkgs, got {}",
            party.params.n - 1,
            r1_pkgs.len()
        )));
    }

    let r2_pkgs = st
        .round2_pkgs
        .remove(&party.id)
        .ok_or("missing round2 pkgs")?;

    if r2_pkgs.len() != (party.params.n as usize - 1) {
        return Err(Error(format!(
            "expected {} round2 pkgs, got {}",
            party.params.n - 1,
            r2_pkgs.len()
        )));
    }

    let (key_pkg, pubkey_pkg) =
        dkg::part3(&sec2, &r1_pkgs, &r2_pkgs).map_err(|e| Error(format!("dkg part3: {e:?}")))?;

    party.key_pkg = Some(key_pkg.clone());
    party.pubkey_pkg = Some(pubkey_pkg.clone());
    st.key_pkg = Some(key_pkg.clone());
    st.pubkey_pkg = Some(pubkey_pkg.clone());
    st.party = Some(party.clone());

    let vk_bytes = pubkey_pkg
        .verifying_key()
        .serialize()
        .map_err(|e| Error(format!("{e:?}")))?;
    let vk_arr: [u8; 32] =
        <[u8; 32]>::try_from(vk_bytes.as_slice()).map_err(|_| Error("vk len".into()))?;
    let dalek = DalekPubkey::from_bytes(&vk_arr).map_err(|_| Error("dalek pk".into()))?;
    let agg = Pubkey::new_from_array(dalek.to_bytes());
    let agg_str: String = agg.to_string();

    println!(
        "Finalized key for node {}, pubkey={}",
        u16_from_id(&party.id),
        agg_str
    );

    let node_id = u16_from_id(&party.id) as i16;
    let placeholder_email = "dkg_generated@system.local";

    match key_pkg.serialize() {
        Ok(key_bytes) => match pubkey_pkg.serialize() {
            Ok(pubkey_bytes) => {
                println!(
                    "Debug: Serializing key_pkg={} bytes, pubkey_pkg={} bytes for node {}",
                    key_bytes.len(),
                    pubkey_bytes.len(),
                    node_id
                );

                if let Err(e) = st
                    .mpc_store
                    .save_dkg_state(&agg_str, placeholder_email, node_id, &key_pkg, &pubkey_pkg)
                    .await
                {
                    println!(
                        "Warning: Failed to auto-save DKG state for node {}: {}",
                        node_id, e
                    );
                } else {
                    println!(
                            "Auto-saved DKG state for node {} with pubkey {} (key={} bytes, pubkey={} bytes)",
                            node_id, agg_str, key_bytes.len(), pubkey_bytes.len()
                        );
                }
            }
            Err(e) => {
                println!("Warning: Failed to serialize pubkey package for debug: {e:?}");
            }
        },
        Err(e) => {
            println!("Warning: Failed to serialize key package for debug: {e:?}");
        }
    }

    Ok(web::Json(Round2Resp {
        id: u16_from_id(&party.id),
        pubkey: agg_str,
    }))
}

#[post("/save-dkg")]
async fn save_dkg_state(
    state: web::Data<Mutex<AppState>>,
    req: web::Json<SaveDkgRequest>,
) -> Result<impl Responder, Error> {
    let st = state.lock().unwrap();

    let party = st.party.as_ref().ok_or("party not initialized")?;
    let key_pkg = st
        .key_pkg
        .as_ref()
        .ok_or("DKG not completed - no key package")?;
    let pubkey_pkg = st
        .pubkey_pkg
        .as_ref()
        .ok_or("DKG not completed - no pubkey package")?;

    let vk_bytes = pubkey_pkg
        .verifying_key()
        .serialize()
        .map_err(|e| Error(format!("serialize vk: {e:?}")))?;
    let vk_arr: [u8; 32] = vk_bytes
        .try_into()
        .map_err(|_| Error("invalid vk length".into()))?;
    let dalek =
        DalekPubkey::from_bytes(&vk_arr).map_err(|_| Error("invalid dalek pubkey".into()))?;
    let pubkey_str = Pubkey::new_from_array(dalek.to_bytes()).to_string();

    let node_id = u16_from_id(&party.id) as i16;

    st.mpc_store
        .save_dkg_state(&pubkey_str, &req.user_email, node_id, key_pkg, pubkey_pkg)
        .await?;

    println!(
        "Saved DKG state for user {} on node {} with pubkey {}",
        req.user_email, node_id, pubkey_str
    );

    Ok(web::Json(serde_json::json!({
        "status": "success",
        "message": "DKG state saved to database",
        "pubkey": pubkey_str,
        "node_id": node_id
    })))
}

#[derive(Serialize, Deserialize)]
struct LoadDkgRequest {
    pubkey: String,
}

#[post("/load-dkg")]
async fn load_dkg_state(
    state: web::Data<Mutex<AppState>>,
    req: web::Json<LoadDkgRequest>,
) -> Result<impl Responder, Error> {
    let mut st = state.lock().unwrap();

    let pid: u16 = env::var("PARTY_ID")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .unwrap();
    let node_id = pid as i16;

    match st.mpc_store.load_dkg_packages(&req.pubkey, node_id).await? {
        Some((key_pkg, pubkey_pkg_opt)) => {
            if st.party.is_none() {
                let party = dkg_party_init(pid, st.params)?;
                st.party = Some(party);
            }

            if let Some(ref mut party) = st.party {
                party.key_pkg = Some(key_pkg.clone());
                if let Some(pubkey_pkg) = &pubkey_pkg_opt {
                    party.pubkey_pkg = Some(pubkey_pkg.clone());
                }
            }
            st.key_pkg = Some(key_pkg);
            if let Some(pubkey_pkg) = pubkey_pkg_opt {
                st.pubkey_pkg = Some(pubkey_pkg);
            }

            println!(
                "Loaded DKG state for pubkey {} on node {}",
                req.pubkey, node_id
            );

            Ok(web::Json(serde_json::json!({
                "status": "success",
                "message": "DKG state loaded from database",
                "pubkey": req.pubkey,
                "node_id": node_id
            })))
        }
        None => Ok(web::Json(serde_json::json!({
            "status": "not_found",
            "message": "No DKG state found for this pubkey and node",
            "pubkey": req.pubkey,
            "node_id": node_id
        }))),
    }
}

#[derive(serde::Serialize)]
struct PubkeyResponse {
    pubkey: String,
}

#[get("/pubkey")]
async fn pubkey(state: web::Data<Mutex<AppState>>) -> Result<impl Responder, Error> {
    let st = state.lock().unwrap();
    let pk_pkg = st.pubkey_pkg.clone().ok_or("not finished")?;
    let vk_bytes = pk_pkg
        .verifying_key()
        .serialize()
        .map_err(|e| Error(format!("{e:?}")))?;
    let vk_arr: [u8; 32] =
        <[u8; 32]>::try_from(vk_bytes.as_slice()).map_err(|_| Error("vk len".into()))?;
    let dalek = DalekPubkey::from_bytes(&vk_arr).map_err(|_| Error("dalek pk".into()))?;
    let agg = Pubkey::new_from_array(dalek.to_bytes());
    let agg_str = agg.to_string();

    Ok(web::Json(PubkeyResponse { pubkey: agg_str }))
}

#[post("/sign-round1")]
async fn sign_round1_route(
    state: web::Data<Mutex<AppState>>,
    req: web::Json<SignRound1Req>,
) -> Result<impl Responder, Error> {
    let mut st = state.lock().unwrap();
    let msg = decode_message(&req.message, req.message_format.as_deref())?;
    let key = msg_key(&msg);

    let party = st.party.clone().ok_or("party not ready")?;
    let kp = party.key_pkg.clone().ok_or("no key_pkg")?;
    let mut rng = rand::rngs::OsRng;

    let (nonces, commitments) = round1::commit(kp.signing_share(), &mut rng);

    st.nonces_by_key.insert(key.clone(), nonces.clone());
    st.commits_by_key.insert(key.clone(), commitments.clone());

    let pid = u16_from_id(&party.id);
    Ok(web::Json(CommitmentsMsg {
        id: pid,
        commitments,
    }))
}

#[post("/sign-build")]
async fn sign_build_route(
    state: web::Data<Mutex<AppState>>,
    req: web::Json<SignBuildReq>,
) -> Result<impl Responder, Error> {
    let mut st = state.lock().unwrap();
    let msg = decode_message(&req.message, req.message_format.as_deref())?;
    let key = msg_key(&msg);

    let mut map: BTreeMap<Identifier<Ed25519Sha512>, round1::SigningCommitments> = BTreeMap::new();
    let mut signer_ids: Vec<u16> = Vec::new();

    for c in &req.commitments {
        let id: Identifier<Ed25519Sha512> =
            c.id.try_into()
                .map_err(|_| Error(format!("bad id {}", c.id)))?;
        map.insert(id, c.commitments.clone());
        signer_ids.push(c.id);
    }

    let sp = SigningPackage::new(map, &msg);
    st.sp_by_key.insert(key.clone(), sp);

    Ok(web::Json(SignBuildResp {
        message_key: key,
        signer_ids,
    }))
}

#[post("/sign-round2")]
async fn sign_round2_route(
    state: web::Data<Mutex<AppState>>,
    req: web::Json<SignRound2Req>,
) -> Result<impl Responder, Error> {
    let mut st = state.lock().unwrap();
    let msg = decode_message(&req.message, req.message_format.as_deref())?;
    let key = msg_key(&msg);

    let party = st.party.clone().ok_or("party not ready")?;
    let kp = party.key_pkg.clone().ok_or("no key_pkg")?;
    let local_nonces = st.nonces_by_key.get(&key).ok_or("no local nonces")?.clone();

    let mut map: BTreeMap<Identifier<Ed25519Sha512>, round1::SigningCommitments> = BTreeMap::new();
    for c in &req.commitments {
        let id: Identifier<Ed25519Sha512> =
            c.id.try_into()
                .map_err(|_| Error(format!("bad id {}", c.id)))?;
        map.insert(id, c.commitments.clone());
    }

    let sp = SigningPackage::new(map, &msg);
    let share = round2::sign(&sp, &local_nonces, &kp).map_err(|e| Error(format!("sign: {e:?}")))?;
    let pid = u16_from_id(&party.id);

    st.shares_by_key
        .entry(key.clone())
        .or_default()
        .insert(party.id, share.clone());

    Ok(web::Json(ShareMsg { id: pid, share }))
}

#[post("/aggregate-signatures")]
async fn aggregate_signatures_route(
    state: web::Data<Mutex<AppState>>,
    req: web::Json<AggregateReq>,
) -> Result<impl Responder, Error> {
    let st = state.lock().unwrap();
    let msg = decode_message(&req.message, req.message_format.as_deref())?;
    let _key = msg_key(&msg);

    let pk_pkg = st.pubkey_pkg.clone().ok_or("no pubkey_pkg")?;

    let mut commits_map: BTreeMap<Identifier<Ed25519Sha512>, round1::SigningCommitments> =
        BTreeMap::new();
    for c in &req.commitments {
        let id: Identifier<Ed25519Sha512> =
            c.id.try_into()
                .map_err(|_| Error(format!("bad id {}", c.id)))?;
        commits_map.insert(id, c.commitments.clone());
    }
    let sp = SigningPackage::new(commits_map, &msg);

    let mut shares_map: BTreeMap<Identifier<Ed25519Sha512>, round2::SignatureShare> =
        BTreeMap::new();
    for s in &req.shares {
        let id: Identifier<Ed25519Sha512> =
            s.id.try_into()
                .map_err(|_| Error(format!("bad id {}", s.id)))?;
        shares_map.insert(id, s.share.clone());
    }

    let sig: Signature = frost::aggregate(&sp, &shares_map, &pk_pkg)
        .map_err(|e| Error(format!("aggregate: {e:?}")))?;

    let sig_bytes = sig
        .serialize()
        .map_err(|e| Error(format!("serialize: {e:?}")))?;
    let arr: [u8; 64] =
        <[u8; 64]>::try_from(sig_bytes.as_slice()).map_err(|_| Error("sig len".into()))?;

    use solana_sdk::signature::Signature as SolSig;
    let sol = SolSig::try_from(arr.as_slice()).map_err(|_| Error("sol sig".into()))?;

    Ok(web::Json(AggregateResp {
        signature_hex: hex::encode(arr),
        signature_base64: {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(arr)
        },
        solana_signature: sol.to_string(),
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "8081".to_string())
        .parse()
        .expect("Invalid PORT");
    let pid: u16 = env::var("PARTY_ID")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .expect("Invalid PARTY_ID");
    let params = ThresholdParams { t: 2, n: 3 };

    let mpc_db_url = env::var("MPC_DATABASE_URL")
        .unwrap_or_else(|_| format!("postgres://mpc:mpcpass@localhost:543{}/mpc{}", 2 + pid, pid));

    println!("Connecting to MPC database: {}", mpc_db_url);
    let mpc_pool = PgPool::connect(&mpc_db_url)
        .await
        .expect("Failed to connect to MPC database");

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS "MPCKeys" (
            pubkey TEXT NOT NULL,
            user_email TEXT NOT NULL,
            node_id SMALLINT NOT NULL,
            key_pkg BYTEA NOT NULL,
            pubkey_pkg BYTEA NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (pubkey, node_id)
        );
        "#,
    )
    .execute(&mpc_pool)
    .await
    .expect("Failed to create MPCKeys table");

    let mpc_store = MPCStore { pool: mpc_pool };

    let initial_state = AppState {
        params,
        party: None,
        round1: None,
        pubkey_pkg: None,
        key_pkg: None,
        nonces_by_key: HashMap::new(),
        commits_by_key: HashMap::new(),
        sp_by_key: HashMap::new(),
        shares_by_key: HashMap::new(),
        round2_pkgs: HashMap::new(),
        all_r1: BTreeMap::new(),
        mpc_store,
    };

    println!("MPC server {pid} starting on port {port}");
    let state = web::Data::new(Mutex::new(initial_state));

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .service(dkg_round1_route)
            .service(dkg_round2_init)
            .service(dkg_round2_recv)
            .service(dkg_finalize)
            .service(save_dkg_state)
            .service(load_dkg_state)
            .service(pubkey)
            .service(sign_round1_route)
            .service(sign_build_route)
            .service(sign_round2_route)
            .service(aggregate_signatures_route)
    })
    .bind(("127.0.0.1", port))?
    .run()
    .await
}
