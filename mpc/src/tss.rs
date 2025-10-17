#![allow(non_snake_case)]

use std::collections::BTreeMap;

use ed25519_dalek::{Signature as DalekSig, Verifier, VerifyingKey as DalekPubkey};
use frost::{
    keys::{dkg, KeyPackage, PublicKeyPackage},
    round1::{self, SigningCommitments, SigningNonces},
    round2, Identifier, Signature, SigningPackage,
};
use frost_ed25519 as frost;
use rand::rngs::OsRng;
use solana_sdk::{
    hash::Hash, pubkey::Pubkey, signature::Signature as SolSignature, signer::Signer, system_instruction, transaction::Transaction
};
use std::convert::TryFrom;

use crate::error::Error;

#[derive(Clone, Copy, Debug)]
pub struct ThresholdParams {
    pub t: u16,
    pub n: u16,
}
#[derive(Clone)]
pub struct FrostParty {
    pub id: Identifier,
    pub index: u16,
    pub params: ThresholdParams,
    pub key_pkg: Option<KeyPackage>,
    pub pubkey_pkg: Option<PublicKeyPackage>,
    round1_secret: Option<dkg::round1::SecretPackage>,
    round2_secret: Option<dkg::round2::SecretPackage>,
}

impl FrostParty {
    pub fn take_round1_secret(&mut self) -> Option<dkg::round1::SecretPackage> {
        self.round1_secret.take()
    }

    pub fn set_round1_secret(&mut self, sec: dkg::round1::SecretPackage) {
        self.round1_secret = Some(sec);
    }

    pub fn take_round2_secret(&mut self) -> Option<dkg::round2::SecretPackage> {
        self.round2_secret.take()
    }

    pub fn set_round2_secret(&mut self, sec: dkg::round2::SecretPackage) {
        self.round2_secret = Some(sec);
    }
}

/// DKG round 1 broadcast (same package sent to all peers).
#[derive(Clone)]
pub struct DkgRound1 {
    pub id: Identifier,
    pub pkg: dkg::round1::Package,
}

/// Result per-party after finishing DKG.
#[derive(Clone)]
pub struct DkgRound2 {
    pub id: Identifier,
    pub key_pkg: KeyPackage,
    pub pubkey_pkg: PublicKeyPackage,
}

/// Round 1 of signing: each signer produces fresh nonces and commitments.
#[derive(Clone)]
pub struct SignRound1 {
    pub id: Identifier,
    pub nonces: SigningNonces,
    pub commitments: SigningCommitments,
}

pub fn dkg_party_init(party_index: u16, params: ThresholdParams) -> Result<FrostParty, Error> {
    let id: Identifier = party_index
        .try_into()
        .map_err(|_| Error("party index must be nonzero <= 65535".into()))?;
    Ok(FrostParty {
        id,
        index: party_index,
        params,
        key_pkg: None,
        pubkey_pkg: None,
        round1_secret: None,
        round2_secret: None,
    })
}

/// DKG part 1 for one party (produces a broadcast package and stores secret state).
pub fn dkg_round1(p: &mut FrostParty) -> Result<DkgRound1, Error> {
    let mut rng = OsRng;
    let (sec, pkg) = dkg::part1(p.id, p.params.n, p.params.t, &mut rng)
        .map_err(|e| Error(format!("dkg part1: {e:?}")))?;
    p.round1_secret = Some(sec);
    Ok(DkgRound1 { id: p.id, pkg })
}

/// Complete DKG for all parties using the gathered part1 broadcasts.
/// Returns per-party key packages + a shared PublicKeyPackage (same for all).
pub fn dkg_round2_all(
    parties: &mut [FrostParty],
    all_r1: &[DkgRound1],
) -> Result<Vec<DkgRound2>, Error> {
    // Build "received round1 packages" mapping: receiver -> (sender -> pkg)
    let mut received_r1: BTreeMap<Identifier, BTreeMap<Identifier, dkg::round1::Package>> =
        BTreeMap::new();
    for r in all_r1 {
        for recv in parties.iter() {
            if recv.id == r.id {
                continue;
            }
            received_r1
                .entry(recv.id)
                .or_default()
                .insert(r.id, r.pkg.clone());
        }
    }

    // Part 2: each participant processes received round1 packages and produces per-recipient packages.
    let mut r2_secrets: BTreeMap<Identifier, dkg::round2::SecretPackage> = BTreeMap::new();
    let mut to_deliver_r2: BTreeMap<Identifier, BTreeMap<Identifier, dkg::round2::Package>> =
        BTreeMap::new();

    for p in parties.iter_mut() {
        let sec1 = p
            .round1_secret
            .take()
            .ok_or_else(|| Error("missing round1 secret".into()))?;
        let r1_pkgs = received_r1
            .get(&p.id)
            .ok_or_else(|| Error("missing received r1 pkgs".into()))?;
        let (sec2, per_recipient) =
            dkg::part2(sec1, r1_pkgs).map_err(|e| Error(format!("dkg part2: {e:?}")))?;
        r2_secrets.insert(p.id, sec2);
        for (recv, pkg) in per_recipient {
            to_deliver_r2.entry(recv).or_default().insert(p.id, pkg);
        }
    }

    // Part 3: finalize key packages and the group public key package.
    let mut out: Vec<DkgRound2> = Vec::with_capacity(parties.len());
    for p in parties.iter_mut() {
        let sec2 = r2_secrets
            .remove(&p.id)
            .ok_or_else(|| Error("missing round2 secret".into()))?;
        let r1_pkgs = received_r1
            .get(&p.id)
            .ok_or_else(|| Error("missing received r1 pkgs".into()))?;
        let r2_pkgs = to_deliver_r2
            .get(&p.id)
            .ok_or_else(|| Error("missing received r2 pkgs".into()))?;
        let (key_pkg, pubkey_pkg) =
            dkg::part3(&sec2, r1_pkgs, r2_pkgs).map_err(|e| Error(format!("dkg part3: {e:?}")))?;

        p.key_pkg = Some(key_pkg.clone());
        p.pubkey_pkg = Some(pubkey_pkg.clone());
        out.push(DkgRound2 {
            id: p.id,
            key_pkg,
            pubkey_pkg,
        });
    }
    Ok(out)
}

/// Aggregate/group public key (Solana Pubkey).
pub fn aggregated_pubkey(any_party: &FrostParty) -> Result<Pubkey, Error> {
    let pk_pkg = any_party
        .pubkey_pkg
        .as_ref()
        .ok_or_else(|| Error("pubkey package not set; run DKG".into()))?;
    // Serialize the verifying key (32 bytes for Ed25519)
    let vk_bytes = pk_pkg
        .verifying_key()
        .serialize()
        .map_err(|e| Error(format!("serialize verifying key: {e:?}")))?;
    let vk_arr: [u8; 32] = vk_bytes
        .try_into()
        .map_err(|_| Error("unexpected verifying key length".into()))?;

    // Normalize via dalek to be extra safe
    let dalek =
        DalekPubkey::from_bytes(&vk_arr).map_err(|_| Error("invalid group pubkey".into()))?;
    Ok(Pubkey::new_from_array(dalek.to_bytes()))
}

/// Signing round 1 for a party: produce fresh nonces + commitments.
/// (Commitments are sent to the coordinator; nonces are kept locally.)
pub fn sign_round1(p: &FrostParty) -> Result<SignRound1, Error> {
    let key_pkg = p
        .key_pkg
        .as_ref()
        .ok_or_else(|| Error("missing key package".into()))?;
    let mut rng = OsRng;
    let (nonces, commitments) = round1::commit(key_pkg.signing_share(), &mut rng);
    Ok(SignRound1 {
        id: p.id,
        nonces,
        commitments,
    })
}

/// Build the signing package (coordinator side) for a specific message and signer set.
pub fn build_signing_package(
    message: &[u8],
    sign_r1_all: &[SignRound1],
    signer_ids: &[u16],
) -> Result<(SigningPackage, BTreeMap<Identifier, SigningNonces>), Error> {
    // Keep only selected signers (must be <= t and unique).
    let mut commitments_map = BTreeMap::new();
    let mut nonces_map = BTreeMap::new();
    for sid in signer_ids {
        let id: Identifier = (*sid)
            .try_into()
            .map_err(|_| Error("bad signer id".into()))?;
        let item = sign_r1_all
            .iter()
            .find(|r| r.id == id)
            .ok_or_else(|| Error("missing round1 for selected signer".into()))?;
        commitments_map.insert(id, item.commitments.clone());
        nonces_map.insert(id, item.nonces.clone());
    }
    let sp = SigningPackage::new(commitments_map, message);
    Ok((sp, nonces_map))
}

/// Each selected participant generates its signature share.
pub fn sign_round2_shares(
    parties: &[FrostParty],
    sp: &SigningPackage,
    nonces_map: &BTreeMap<Identifier, SigningNonces>,
) -> Result<BTreeMap<Identifier, round2::SignatureShare>, Error> {
    let mut sig_shares = BTreeMap::new();
    for (id, nonces) in nonces_map {
        let kp = parties
            .iter()
            .find(|p| p.id == *id)
            .and_then(|p| p.key_pkg.as_ref())
            .ok_or_else(|| Error("missing key package for signer".into()))?;
        let ss = round2::sign(sp, nonces, kp).map_err(|e| Error(format!("round2 sign: {e:?}")))?;
        sig_shares.insert(*id, ss);
    }
    Ok(sig_shares)
}

/// Aggregate signature shares to a standard Ed25519 signature (64 bytes), verify, and return Solana `Signature`.
pub fn finalize_signature_solana(
    parties: &[FrostParty],
    sp: &SigningPackage,
    sig_shares: &BTreeMap<Identifier, round2::SignatureShare>,
) -> Result<SolSignature, Error> {
    // Get common pubkey package (same for all parties).
    let pk_pkg = parties
        .iter()
        .find_map(|p| p.pubkey_pkg.as_ref())
        .ok_or_else(|| Error("missing pubkey package".into()))?;

    // Aggregate (also validates the signature shares internally).
    let group_sig: Signature =
        frost::aggregate(sp, sig_shares, pk_pkg).map_err(|e| Error(format!("aggregate: {e:?}")))?;

    // Serialize signature to bytes
    let sig_bytes = group_sig
        .serialize()
        .map_err(|e| Error(format!("serialize signature: {e:?}")))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| Error("unexpected signature length".into()))?;

    // Optional: verify with dalek before returning (defensive)
    let vk_bytes = pk_pkg
        .verifying_key()
        .serialize()
        .map_err(|e| Error(format!("serialize verifying key: {e:?}")))?;
    let vk_arr: [u8; 32] = vk_bytes
        .try_into()
        .map_err(|_| Error("unexpected verifying key length".into()))?;
    let dalek_pk =
        DalekPubkey::from_bytes(&vk_arr).map_err(|_| Error("invalid pubkey bytes".into()))?;
    let dalek_sig = DalekSig::from_bytes(&sig_arr);
    if let Err(e) = dalek_pk.verify(sp.message(), &dalek_sig) {
        return Err(Error(format!("dalek verify failed: {e:?}")));
    }

    Ok(SolSignature::try_from(sig_arr).map_err(|_| Error("sol sig conversion failed".into()))?)
}

/// Convenience: create a simple SOL transfer (optionally with Memo) unsigned.
pub fn create_unsigned_transaction(
    amount: u64,
    to: &Pubkey,
    memo: Option<String>,
    from: &Pubkey,
    recent_block_hash: Hash,
) -> Transaction {
    let ix = system_instruction::transfer(from, to, amount);
    let memo_ix_opt = memo.map(|m| {
        use solana_sdk::instruction::Instruction;
        let memo_pid = Pubkey::from_str_const("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
        Instruction {
            program_id: memo_pid,
            accounts: vec![],
            data: m.into_bytes(),
        }
    });
    let mut ixs = vec![ix];
    if let Some(memo_ix) = memo_ix_opt {
        ixs.push(memo_ix);
    }
    let mut tx = Transaction::new_with_payer(&ixs, Some(from));
    tx.message.recent_blockhash = recent_block_hash;
    tx
}

/// Attach a FROST signature to a tx and re-verify locally.
pub fn build_signed_tx(
    amount: u64,
    to: Pubkey,
    memo: Option<String>,
    recent_block_hash: Hash,
    agg_pubkey: Pubkey,
    sig: SolSignature,
) -> Result<Transaction, Error> {
    let mut tx = create_unsigned_transaction(amount, &to, memo, &agg_pubkey, recent_block_hash);
    if tx.signatures.len() != 1 {
        return Err(Error("unexpected signature slots".into()));
    }

    // Defensive verification with dalek on message bytes.
    let msg_bytes = tx.message_data();

    let dalek_pk = DalekPubkey::from_bytes(&agg_pubkey.to_bytes())
        .map_err(|_| Error("invalid pubkey".into()))?;

    let sig_bytes: [u8; 64] = sig
        .as_ref()
        .try_into()
        .map_err(|_| Error("sig not 64 bytes".into()))?;

    let dalek_sig =
        DalekSig::try_from(&sig_bytes).map_err(|_| Error("invalid signature".into()))?;

    dalek_pk
        .verify(&msg_bytes, &dalek_sig)
        .map_err(|_| Error("dalek verification failed".into()))?;

    tx.signatures[0] = sig;
    tx.verify().map_err(|_| Error("invalid signature".into()))?;
    Ok(tx)
}

#[test]
fn frost_two_of_three() -> Result<(), crate::error::Error> {
    let params = ThresholdParams { t: 2, n: 3 };

    use solana_sdk::signer::keypair::Keypair;

    // Parties 1..=3
    let mut parties = vec![
        dkg_party_init(1, params)?,
        dkg_party_init(2, params)?,
        dkg_party_init(3, params)?,
    ];

    // DKG part1 (broadcast)
    let r1_1 = dkg_round1(&mut parties[0])?;
    let r1_2 = dkg_round1(&mut parties[1])?;
    let r1_3 = dkg_round1(&mut parties[2])?;
    let _r2 = dkg_round2_all(&mut parties, &[r1_1, r1_2, r1_3])?;

    // Aggregated (group) pubkey
    let agg_pk = aggregated_pubkey(&parties[0])?;

    // Build unsigned tx FIRST
    let to = Keypair::new().pubkey();
    let bh = Hash::new_unique();
    let tx = create_unsigned_transaction(1_000, &to, None, &agg_pk, bh);

    // The EXACT bytes that Solana verifies:
    let msg_bytes = tx.message_data();

    // Round 1: nonces/commitments for chosen signers (say {1,3})
    let s1 = sign_round1(&parties[0])?;
    let s3 = sign_round1(&parties[2])?;

    // Build signing package for {1,3} over tx.message_data()
    let (sp, nonces_map) = build_signing_package(&msg_bytes, &[s1.clone(), s3.clone()], &[1, 3])?;

    // Round 2: signature shares
    let sig_shares = sign_round2_shares(&parties, &sp, &nonces_map)?;

    // Aggregate to group signature (64 bytes)
    let sol_sig = finalize_signature_solana(&parties, &sp, &sig_shares)?;

    // Sanity: dalek verify over the SAME msg_bytes
    let dalek_pk = DalekPubkey::from_bytes(&agg_pk.to_bytes())
        .map_err(|e| Error(format!("invalid pubkey: {e}")))?;
    let sig_arr: [u8; 64] = sol_sig.as_ref().try_into().unwrap();
    let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    assert!(dalek_pk.verify(&msg_bytes, &dalek_sig).is_ok());

    // Attach to tx and verify with Solana's checker
    let mut tx2 = tx.clone();
    tx2.signatures[0] = sol_sig;
    assert!(tx2.verify().is_ok());

    Ok(())
}
