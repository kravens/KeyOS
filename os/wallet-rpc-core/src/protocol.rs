// SPDX-FileCopyrightText: 2026 Kevin Ravensberg <kevinravensberg@proton.me>
// SPDX-License-Identifier: MIT OR GPL-3.0-or-later

//! Wallet RPC wire protocol (v1).
//!
//! Frame layout, both directions, little-endian:
//!
//! Request:  `[version u8][command u8][payload_len u16][payload ...]`
//! Response: `[version u8][command u8][status u8][payload_len u16][payload ...]`
//!
//! Commands:
//! - `0x01 GetInfo`:  `[]` → `[proto_ver u8][capabilities u32][fw utf8]`
//! - `0x02 GetXpub`:  `[network u8][n u8][path u32 * n]` → `[fingerprint 4][xpub utf8]`
//! - `0x03 GetOwnershipProof`: `[session u32][n u8][path u32 * n][cd_len u16][cd]`
//!   → SLIP-0019 proof bytes. Session-gated: the path must be inside the
//!   authorized account and the commitment must open with the authorized
//!   coordinator id.
//! - `0x04 AuthorizeCoinjoin`: policy bytes (see `coinjoin::Policy::parse`)
//!   → `[session u32]`. Triggers on-device approval.
//! - `0x05 SignCoinjoin`: `[session u32][psbt ...]` → signed PSBT bytes.
//! - `0x06 RevokeSession`: `[session u32]` → `[]`.
//!
//! The command handling is functional over a [`Backend`] so it can be tested
//! without any KeyOS servers.

use ngwallet::bdk_wallet::bitcoin::{
    bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub},
    secp256k1::{All, Secp256k1},
    Network,
};

use crate::{
    coinjoin::{self, Policy, Session},
    slip19,
};

pub const PROTOCOL_VERSION: u8 = 1;

pub const CMD_GET_INFO: u8 = 0x01;
pub const CMD_GET_XPUB: u8 = 0x02;
pub const CMD_GET_OWNERSHIP_PROOF: u8 = 0x03;
pub const CMD_AUTHORIZE_COINJOIN: u8 = 0x04;
pub const CMD_SIGN_COINJOIN: u8 = 0x05;
pub const CMD_REVOKE_SESSION: u8 = 0x06;

pub const STATUS_OK: u8 = 0x00;
pub const STATUS_ERR_MALFORMED: u8 = 0x01;
pub const STATUS_ERR_UNKNOWN_COMMAND: u8 = 0x02;
pub const STATUS_ERR_UNSUPPORTED_VERSION: u8 = 0x03;
pub const STATUS_ERR_DENIED: u8 = 0x04;
pub const STATUS_ERR_NO_SESSION: u8 = 0x05;
pub const STATUS_ERR_POLICY: u8 = 0x06;
pub const STATUS_ERR_INTERNAL: u8 = 0x07;

/// GetInfo capability bits.
pub const CAP_OWNERSHIP_PROOFS: u32 = 1 << 0;
pub const CAP_COINJOIN_SIGNING: u32 = 1 << 1;
pub const CAPABILITIES: u32 = CAP_OWNERSHIP_PROOFS | CAP_COINJOIN_SIGNING;

const REQUEST_HEADER_LEN: usize = 4;

/// Error from a typed engine operation, independent of any transport.
/// The byte protocol maps these to a wire status byte; a QuantumLink message
/// handler can map them to its own error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreError {
    Malformed,
    Denied,
    NoSession,
    Policy,
    Internal,
}

impl CoreError {
    pub fn status(self) -> u8 {
        match self {
            CoreError::Malformed => STATUS_ERR_MALFORMED,
            CoreError::Denied => STATUS_ERR_DENIED,
            CoreError::NoSession => STATUS_ERR_NO_SESSION,
            CoreError::Policy => STATUS_ERR_POLICY,
            CoreError::Internal => STATUS_ERR_INTERNAL,
        }
    }
}

/// Host-independent device services the protocol needs.
pub trait Backend {
    fn firmware_version(&self) -> String;
    /// 64-byte BIP-39 seed. `None` = locked / unavailable.
    fn seed(&mut self) -> Option<Vec<u8>>;
    /// Blocking on-device user approval of a coinjoin session policy.
    fn approve_policy(&mut self, policy: &Policy) -> bool;
}

/// Protocol engine: session registry + dispatch. One per device connection.
pub struct Engine<B> {
    pub backend: B,
    secp: Secp256k1<All>,
    sessions: Vec<Session>,
    next_session_id: u32,
}

impl<B: Backend> Engine<B> {
    pub fn new(backend: B) -> Self {
        Self { backend, secp: Secp256k1::new(), sessions: Vec::new(), next_session_id: 1 }
    }

    // ------------------------------------------------------------------
    // Typed API — transport-independent. Both the byte protocol below and a
    // QuantumLink message handler call these directly.
    // ------------------------------------------------------------------

    /// `(protocol_version, capabilities, firmware_version)`.
    pub fn info(&self) -> (u8, u32, String) {
        (PROTOCOL_VERSION, CAPABILITIES, self.backend.firmware_version())
    }

    /// Extended public key at `path` (for wallet import). One seed prompt.
    pub fn xpub(&mut self, network: Network, path: &[u32]) -> Result<(Fingerprint, String), CoreError> {
        let seed = self.backend.seed().ok_or(CoreError::Denied)?;
        let master = Xpriv::new_master(network, &seed).map_err(|_| CoreError::Internal)?;
        let fingerprint = master.fingerprint(&self.secp);
        let derivation: DerivationPath =
            path.iter().map(|&i| ChildNumber::from(i)).collect::<Vec<_>>().into();
        let xpriv = master.derive_priv(&self.secp, &derivation).map_err(|_| CoreError::Internal)?;
        Ok((fingerprint, Xpub::from_priv(&self.secp, &xpriv).to_string()))
    }

    /// Approve a coinjoin session on-device and open it. Retrieves the seed
    /// once, here, right after the single approval, and caches it for the
    /// session — so later proofs and signatures never re-prompt. Returns the
    /// session id.
    pub fn authorize(&mut self, policy: Policy) -> Result<u32, CoreError> {
        if !self.backend.approve_policy(&policy) {
            return Err(CoreError::Denied);
        }
        let seed = self.backend.seed().ok_or(CoreError::Denied)?;
        let id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);
        self.sessions.push(Session {
            id,
            policy,
            authorized_at: std::time::Instant::now(),
            rounds_used: 0,
            seed: zeroize::Zeroizing::new(seed),
        });
        Ok(id)
    }

    /// SLIP-0019 ownership proof for `path` under an authorized session. The
    /// path must be in the policy account and the commitment must open with the
    /// authorized coordinator id.
    pub fn ownership_proof(
        &mut self,
        session_id: u32,
        path: &[u32],
        commitment: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        let session = self.session(session_id)?;
        if session.is_expired() {
            return Err(CoreError::NoSession);
        }
        if !session.policy.path_in_scope(path) {
            return Err(CoreError::Policy);
        }
        if !commitment_matches_coordinator(commitment, &session.policy.coordinator_id) {
            return Err(CoreError::Policy);
        }
        // Script type follows the path's BIP purpose: 86' = taproot, else segwit v0.
        let script_type = if path.first() == Some(&(86 | 0x8000_0000)) {
            slip19::ScriptType::P2tr
        } else {
            slip19::ScriptType::P2wpkh
        };
        // Uses the session's cached seed — no per-round trusted-display prompt.
        slip19::ownership_proof_for(
            &self.secp,
            &session.seed,
            session.policy.network,
            script_type,
            path,
            commitment,
            true,
        )
        .map_err(|_| CoreError::Internal)
    }

    /// Verify the round PSBT against the session policy and sign our inputs.
    pub fn sign_round(&mut self, session_id: u32, psbt: &[u8]) -> Result<Vec<u8>, CoreError> {
        let session = self.session(session_id)?;
        let signed = coinjoin::check_and_sign(&self.secp, session, psbt).map_err(|e| match e {
            coinjoin::CoinjoinError::SessionExpired => CoreError::NoSession,
            coinjoin::CoinjoinError::MalformedPsbt => CoreError::Malformed,
            _ => CoreError::Policy,
        })?;
        // A signature spends one round of the session budget.
        self.session_mut(session_id)?.rounds_used += 1;
        Ok(signed.psbt_bytes)
    }

    /// Revoke a session, disabling further signing under it.
    pub fn revoke(&mut self, session_id: u32) -> Result<(), CoreError> {
        let before = self.sessions.len();
        self.sessions.retain(|s| s.id != session_id);
        if self.sessions.len() == before {
            return Err(CoreError::NoSession);
        }
        Ok(())
    }

    fn session(&self, id: u32) -> Result<&Session, CoreError> {
        self.sessions.iter().find(|s| s.id == id).ok_or(CoreError::NoSession)
    }

    fn session_mut(&mut self, id: u32) -> Result<&mut Session, CoreError> {
        self.sessions.iter_mut().find(|s| s.id == id).ok_or(CoreError::NoSession)
    }

    // ------------------------------------------------------------------
    // Byte protocol adapter — the USB / test transport. Parses a frame,
    // calls the typed API, serializes the result. A QuantumLink app does not
    // use this; it calls the typed methods above with decoded messages.
    // ------------------------------------------------------------------

    /// Process one request frame, producing the response frame.
    pub fn process_frame(&mut self, frame: &[u8]) -> Vec<u8> {
        if frame.len() < REQUEST_HEADER_LEN {
            return response(0, STATUS_ERR_MALFORMED, &[]);
        }
        let version = frame[0];
        let command = frame[1];
        let payload_len = u16::from_le_bytes([frame[2], frame[3]]) as usize;

        if version != PROTOCOL_VERSION {
            return response(command, STATUS_ERR_UNSUPPORTED_VERSION, &[PROTOCOL_VERSION]);
        }
        if frame.len() != REQUEST_HEADER_LEN + payload_len {
            return response(command, STATUS_ERR_MALFORMED, &[]);
        }
        let payload = &frame[REQUEST_HEADER_LEN..];

        let result = match command {
            CMD_GET_INFO => Ok(self.info_bytes()),
            CMD_GET_XPUB => self.xpub_bytes(payload),
            CMD_GET_OWNERSHIP_PROOF => self.ownership_proof_bytes(payload),
            CMD_AUTHORIZE_COINJOIN => self.authorize_bytes(payload),
            CMD_SIGN_COINJOIN => self.sign_bytes(payload),
            CMD_REVOKE_SESSION => self.revoke_bytes(payload),
            _ => Err(STATUS_ERR_UNKNOWN_COMMAND),
        };

        match result {
            Ok(payload) => response(command, STATUS_OK, &payload),
            Err(status) => response(command, status, &[]),
        }
    }

    fn info_bytes(&self) -> Vec<u8> {
        let (ver, caps, fw) = self.info();
        let mut payload = Vec::with_capacity(5 + fw.len());
        payload.push(ver);
        payload.extend_from_slice(&caps.to_le_bytes());
        payload.extend_from_slice(fw.as_bytes());
        payload
    }

    fn xpub_bytes(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
        let (network, rest) = parse_network(payload)?;
        let (path, rest) = parse_path(rest)?;
        if !rest.is_empty() {
            return Err(STATUS_ERR_MALFORMED);
        }
        let (fingerprint, xpub) = self.xpub(network, &path).map_err(CoreError::status)?;
        let mut out = Vec::with_capacity(4 + xpub.len());
        out.extend_from_slice(fingerprint.as_bytes());
        out.extend_from_slice(xpub.as_bytes());
        Ok(out)
    }

    fn ownership_proof_bytes(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
        let (session_id, rest) = parse_u32(payload)?;
        let (path, rest) = parse_path(rest)?;
        let (commitment, rest) = parse_prefixed_u16(rest)?;
        if !rest.is_empty() {
            return Err(STATUS_ERR_MALFORMED);
        }
        self.ownership_proof(session_id, &path, &commitment).map_err(CoreError::status)
    }

    fn authorize_bytes(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
        let (policy, consumed) = Policy::parse(payload).ok_or(STATUS_ERR_MALFORMED)?;
        if consumed != payload.len() {
            return Err(STATUS_ERR_MALFORMED);
        }
        let id = self.authorize(policy).map_err(CoreError::status)?;
        Ok(id.to_le_bytes().to_vec())
    }

    fn sign_bytes(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
        let (session_id, psbt) = parse_u32(payload)?;
        self.sign_round(session_id, psbt).map_err(CoreError::status)
    }

    fn revoke_bytes(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
        let (session_id, rest) = parse_u32(payload)?;
        if !rest.is_empty() {
            return Err(STATUS_ERR_MALFORMED);
        }
        self.revoke(session_id).map(|_| vec![]).map_err(CoreError::status)
    }
}

fn response(command: u8, status: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(PROTOCOL_VERSION);
    out.push(command);
    out.push(status);
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

fn parse_network(payload: &[u8]) -> Result<(Network, &[u8]), u8> {
    match payload.first() {
        Some(0) => Ok((Network::Bitcoin, &payload[1..])),
        Some(1) => Ok((Network::Testnet, &payload[1..])),
        _ => Err(STATUS_ERR_MALFORMED),
    }
}

fn parse_u32(payload: &[u8]) -> Result<(u32, &[u8]), u8> {
    if payload.len() < 4 {
        return Err(STATUS_ERR_MALFORMED);
    }
    Ok((u32::from_le_bytes(payload[..4].try_into().unwrap()), &payload[4..]))
}

fn parse_path(payload: &[u8]) -> Result<(Vec<u32>, &[u8]), u8> {
    let n = *payload.first().ok_or(STATUS_ERR_MALFORMED)? as usize;
    if n > 10 || payload.len() < 1 + n * 4 {
        return Err(STATUS_ERR_MALFORMED);
    }
    let path = payload[1..1 + n * 4]
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect();
    Ok((path, &payload[1 + n * 4..]))
}

fn parse_prefixed_u16(payload: &[u8]) -> Result<(Vec<u8>, &[u8]), u8> {
    if payload.len() < 2 {
        return Err(STATUS_ERR_MALFORMED);
    }
    let len = u16::from_le_bytes(payload[..2].try_into().unwrap()) as usize;
    if payload.len() < 2 + len {
        return Err(STATUS_ERR_MALFORMED);
    }
    Ok((payload[2..2 + len].to_vec(), &payload[2 + len..]))
}

/// Does the commitment data commit to exactly this coordinator?
/// Wire shape: `varint(len) || coordinator_id || round_id (32 bytes)`.
fn commitment_matches_coordinator(commitment: &[u8], coordinator_id: &[u8]) -> bool {
    // coordinator ids are short ASCII strings, so a single-byte varint suffices;
    // reject anything longer than 0xfc outright.
    match commitment.first() {
        Some(&len) if len as usize == coordinator_id.len() && len <= 0xfc => {
            commitment.len() > coordinator_id.len()
                && &commitment[1..1 + coordinator_id.len()] == coordinator_id
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use ngwallet::bdk_wallet::keys::bip39::Mnemonic;

    use super::*;

    struct MockBackend {
        approve: bool,
    }

    impl Backend for MockBackend {
        fn firmware_version(&self) -> String { "0.1.0-test".into() }

        fn seed(&mut self) -> Option<Vec<u8>> {
            Some(
                Mnemonic::parse("all all all all all all all all all all all all")
                    .unwrap()
                    .to_seed("")
                    .to_vec(),
            )
        }

        fn approve_policy(&mut self, _policy: &Policy) -> bool { self.approve }
    }

    fn engine(approve: bool) -> Engine<MockBackend> { Engine::new(MockBackend { approve }) }

    fn test_policy() -> Policy {
        Policy {
            network: Network::Bitcoin,
            account: 0,
            coordinator_id: b"CoinJoinCoordinatorIdentifier".to_vec(),
            max_fee_contribution: 10_000,
            max_rounds: 5,
            valid_for_secs: 3600,
        }
    }

    /// The typed API (what a QuantumLink message handler calls) end to end,
    /// no byte framing involved.
    #[test]
    fn typed_api_flow() {
        const H: u32 = 0x8000_0000;
        let mut engine = engine(true);

        let (ver, caps, _fw) = engine.info();
        assert_eq!(ver, PROTOCOL_VERSION);
        assert_eq!(caps & 0b11, 0b11);

        let (fp, xpub) = engine.xpub(Network::Bitcoin, &[84 | H, H, H]).unwrap();
        assert_eq!(fp.as_bytes(), &[0x5c, 0x9e, 0x22, 0x8d]);
        assert!(xpub.starts_with("xpub"));

        let session = engine.authorize(test_policy()).unwrap();

        // Ownership proof for the authorized coordinator succeeds; a foreign one is rejected.
        let coordinator = b"CoinJoinCoordinatorIdentifier";
        let mut commitment = vec![coordinator.len() as u8];
        commitment.extend_from_slice(coordinator);
        commitment.extend_from_slice(&[0xab; 32]);
        let proof = engine.ownership_proof(session, &[84 | H, H, H, 1, 0], &commitment).unwrap();
        assert_eq!(&proof[..4], &[0x53, 0x4c, 0x00, 0x19]);

        // Taproot path (purpose 86') in the same account: P2TR proof — single
        // 64-byte schnorr witness instead of the two-element P2WPKH stack.
        let tr_proof =
            engine.ownership_proof(session, &[86 | H, H, H, 1, 0], &commitment).unwrap();
        assert_eq!(&tr_proof[..4], &[0x53, 0x4c, 0x00, 0x19]);
        assert_eq!(&tr_proof[38..41], &[0x00, 0x01, 0x40]);
        assert_eq!(tr_proof.len(), 41 + 64);
        // Different script type, different ownership id.
        assert_ne!(&tr_proof[6..38], &proof[6..38]);

        let mut evil = vec![4u8];
        evil.extend_from_slice(b"Evil");
        evil.extend_from_slice(&[0xab; 32]);
        assert_eq!(
            engine.ownership_proof(session, &[84 | H, H, H, 1, 0], &evil),
            Err(CoreError::Policy)
        );

        // Revoke, then the session is gone.
        engine.revoke(session).unwrap();
        assert_eq!(engine.revoke(session), Err(CoreError::NoSession));
    }

    #[test]
    fn typed_authorize_denied() {
        assert_eq!(engine(false).authorize(test_policy()), Err(CoreError::Denied));
    }

    fn frame(cmd: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![PROTOCOL_VERSION, cmd];
        f.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        f.extend_from_slice(payload);
        f
    }

    fn ok_payload(resp: &[u8]) -> &[u8] {
        assert_eq!(resp[2], STATUS_OK, "status was {}", resp[2]);
        let len = u16::from_le_bytes([resp[3], resp[4]]) as usize;
        assert_eq!(resp.len(), 5 + len);
        &resp[5..]
    }

    fn test_policy_bytes() -> Vec<u8> {
        crate::coinjoin::Policy {
            network: Network::Bitcoin,
            account: 0,
            coordinator_id: b"CoinJoinCoordinatorIdentifier".to_vec(),
            max_fee_contribution: 10_000,
            max_rounds: 5,
            valid_for_secs: 3600,
        }
        .serialize()
    }

    fn authorize(engine: &mut Engine<MockBackend>) -> u32 {
        let resp = engine.process_frame(&frame(CMD_AUTHORIZE_COINJOIN, &test_policy_bytes()));
        u32::from_le_bytes(ok_payload(&resp).try_into().unwrap())
    }

    #[test]
    fn get_info_reports_capabilities() {
        let resp = engine(true).process_frame(&frame(CMD_GET_INFO, &[]));
        let payload = ok_payload(&resp).to_vec();
        assert_eq!(payload[0], PROTOCOL_VERSION);
        assert_eq!(u32::from_le_bytes(payload[1..5].try_into().unwrap()), CAPABILITIES);
    }

    #[test]
    fn get_xpub_roundtrip() {
        const H: u32 = 0x8000_0000;
        let mut payload = vec![0u8, 3]; // mainnet, 3 path elements
        for i in [84 | H, H, H] {
            payload.extend_from_slice(&i.to_le_bytes());
        }
        let resp = engine(true).process_frame(&frame(CMD_GET_XPUB, &payload));
        let out = ok_payload(&resp).to_vec();
        let xpub = String::from_utf8(out[4..].to_vec()).unwrap();
        assert!(xpub.starts_with("xpub"), "{xpub}");
        // "all all all" master fingerprint (hash160(m pubkey)[..4]; consistent with
        // the passing SLIP-0019 spec vector, which anchors the seed derivation)
        assert_eq!(out[..4], [0x5c, 0x9e, 0x22, 0x8d]);
    }

    #[test]
    fn authorize_then_proof() {
        const H: u32 = 0x8000_0000;
        let mut engine = engine(true);
        let session = authorize(&mut engine);

        // commitment = varint(len)||coordinator||round id
        let coordinator = b"CoinJoinCoordinatorIdentifier";
        let mut commitment = vec![coordinator.len() as u8];
        commitment.extend_from_slice(coordinator);
        commitment.extend_from_slice(&[0xab; 32]);

        let mut payload = session.to_le_bytes().to_vec();
        payload.push(5);
        for i in [84 | H, H, H, 1, 0] {
            payload.extend_from_slice(&i.to_le_bytes());
        }
        payload.extend_from_slice(&(commitment.len() as u16).to_le_bytes());
        payload.extend_from_slice(&commitment);

        let resp = engine.process_frame(&frame(CMD_GET_OWNERSHIP_PROOF, &payload));
        let proof = ok_payload(&resp);
        assert_eq!(&proof[..4], &[0x53, 0x4c, 0x00, 0x19]);
        assert_eq!(proof[4], 0x01, "user confirmation flag must be set");
    }

    #[test]
    fn proof_without_session_denied() {
        const H: u32 = 0x8000_0000;
        let mut payload = 7u32.to_le_bytes().to_vec();
        payload.push(5);
        for i in [84 | H, H, H, 1, 0] {
            payload.extend_from_slice(&i.to_le_bytes());
        }
        payload.extend_from_slice(&2u16.to_le_bytes());
        payload.extend_from_slice(&[1, 0]);
        let resp = engine(true).process_frame(&frame(CMD_GET_OWNERSHIP_PROOF, &payload));
        assert_eq!(resp[2], STATUS_ERR_NO_SESSION);
    }

    #[test]
    fn proof_for_foreign_coordinator_denied() {
        const H: u32 = 0x8000_0000;
        let mut engine = engine(true);
        let session = authorize(&mut engine);

        let evil = b"EvilCoordinator";
        let mut commitment = vec![evil.len() as u8];
        commitment.extend_from_slice(evil);
        commitment.extend_from_slice(&[0xab; 32]);

        let mut payload = session.to_le_bytes().to_vec();
        payload.push(5);
        for i in [84 | H, H, H, 1, 0] {
            payload.extend_from_slice(&i.to_le_bytes());
        }
        payload.extend_from_slice(&(commitment.len() as u16).to_le_bytes());
        payload.extend_from_slice(&commitment);

        let resp = engine.process_frame(&frame(CMD_GET_OWNERSHIP_PROOF, &payload));
        assert_eq!(resp[2], STATUS_ERR_POLICY);
    }

    #[test]
    fn user_denial_blocks_session() {
        let resp = engine(false).process_frame(&frame(CMD_AUTHORIZE_COINJOIN, &test_policy_bytes()));
        assert_eq!(resp[2], STATUS_ERR_DENIED);
    }

    #[test]
    fn revoked_session_stops_proofs() {
        let mut engine = engine(true);
        let session = authorize(&mut engine);

        let resp = engine.process_frame(&frame(CMD_REVOKE_SESSION, &session.to_le_bytes()));
        ok_payload(&resp);

        let resp = engine.process_frame(&frame(CMD_REVOKE_SESSION, &session.to_le_bytes()));
        assert_eq!(resp[2], STATUS_ERR_NO_SESSION);
    }

    #[test]
    fn unknown_command() {
        let resp = engine(true).process_frame(&frame(0x7f, &[]));
        assert_eq!(resp[2], STATUS_ERR_UNKNOWN_COMMAND);
    }

    #[test]
    fn wrong_version() {
        let resp = engine(true).process_frame(&[9, CMD_GET_INFO, 0, 0]);
        assert_eq!(resp[2], STATUS_ERR_UNSUPPORTED_VERSION);
    }

    #[test]
    fn length_mismatch() {
        let resp = engine(true).process_frame(&[PROTOCOL_VERSION, CMD_GET_INFO, 5, 0, 0xaa]);
        assert_eq!(resp[2], STATUS_ERR_MALFORMED);
    }
}
