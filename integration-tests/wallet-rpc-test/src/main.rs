// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration test for the coinjoin remote signer against the real
//! `security-server` seed source. It provisions a seed, then drives
//! `wallet_rpc_core::Engine` (the same engine the USB server and the Coinjoin
//! Signer app wrap) through the full desktop-wallet flow: authorize a session,
//! fetch an xpub, request segwit and taproot ownership proofs, sign a coinjoin
//! PSBT, and confirm a foreign-coordinator proof is rejected. This exercises
//! the one piece unit tests can't: the security-server → BIP-39 seed → account
//! key derivation that produces the signing key on real hardware.

use std::thread;
use std::time::Duration;

use keyos_integration_test::{assert_eq, fail, pass};
use ngwallet::bdk_wallet::{
    bitcoin::{
        absolute::LockTime,
        bip32::{ChildNumber, DerivationPath, Xpriv},
        hashes::Hash,
        psbt::Psbt,
        secp256k1::{All, Secp256k1},
        transaction::Version,
        Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxOut, Txid,
    },
    keys::bip39::Mnemonic,
};
use wallet_rpc_core::{
    coinjoin::{Policy, TOKEN_LEN},
    protocol::{
        Backend, Engine, CMD_AUTHORIZE_COINJOIN, CMD_GET_INFO, CMD_GET_OWNERSHIP_PROOF,
        CMD_GET_XPUB, CMD_SIGN_COINJOIN, PROTOCOL_VERSION, STATUS_ERR_POLICY, STATUS_OK,
    },
    slip19::ScriptType,
};
use zeroize::Zeroizing;

security::use_api!();

const H: u32 = 0x8000_0000;
const MNEMONIC: &str = "all all all all all all all all all all all all";
const COORDINATOR: &[u8] = b"CoinJoinCoordinatorIdentifier";

/// Backend that reads the real device seed from `security-server` (mirrors the
/// server crate's `KeyOsBackend` and the app's `PrimeBackend`) and auto-approves
/// policies (no GUI in tests).
struct SecurityBackend {
    security: Security,
    secp: Secp256k1<All>,
}

impl Backend for SecurityBackend {
    fn firmware_version(&self) -> String {
        "integration-test".into()
    }

    fn seed(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        let entropy = self.security.seed().ok()??;
        let master = ngwallet::bip39::MasterKey::from_entropy(
            &self.secp,
            Network::Bitcoin,
            entropy.bytes(),
            "",
            None,
        )
        .ok()?;
        Some(Zeroizing::new(master.key.0.to_vec()))
    }

    fn approve_policy(&mut self, _policy: &Policy) -> bool {
        true
    }

    fn random_bytes(&mut self, out: &mut [u8]) -> bool {
        match self.security.get_random() {
            Ok(random) if random.len() >= out.len() => {
                out.copy_from_slice(&random[..out.len()]);
                true
            }
            _ => false,
        }
    }
}

fn main() {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Debug);

    thread::sleep(Duration::from_secs(1));

    // Provision the device seed via the real security server.
    let mnemonic = Mnemonic::parse(MNEMONIC).unwrap();
    let entropy = mnemonic.to_entropy();
    let security = Security::default();
    security
        .set_seed_and_pin(
            security::Seed::from_bytes(&entropy),
            "123456".to_string(),
            security::PinEntryMode::Pin,
        )
        .expect("set seed");
    log::info!("Seed provisioned via security-server");

    let mut engine = Engine::new(SecurityBackend { security, secp: Secp256k1::new() });

    // GetInfo advertises coinjoin capabilities.
    let payload = expect_ok(&mut engine, CMD_GET_INFO, &[]);
    assert_eq!(payload[0], PROTOCOL_VERSION, "protocol version");
    let caps = u32::from_le_bytes(payload[1..5].try_into().unwrap());
    assert_eq!(caps & 0b111, 0b111, "ownership + coinjoin + taproot capabilities");

    // Authorize a coinjoin session. The response is the random session token;
    // the seed was read exactly once, here, to derive the account keys.
    let token = expect_ok(&mut engine, CMD_AUTHORIZE_COINJOIN, &policy_bytes());
    assert_eq!(token.len(), TOKEN_LEN, "session token length");
    if token.iter().all(|&b| b == 0) {
        fail!("session token is all zeroes — no entropy from the secure element");
    }
    log::info!("Session authorized, token {} bytes", token.len());

    // Account xpub for wallet import.
    let mut payload = vec![0u8, 3];
    for i in [84 | H, H, H] {
        payload.extend_from_slice(&i.to_le_bytes());
    }
    let xpub_resp = expect_ok(&mut engine, CMD_GET_XPUB, &payload);
    let xpub = String::from_utf8(xpub_resp[4..].to_vec()).unwrap();
    if !xpub.starts_with("xpub") {
        fail!("bad xpub: {xpub}");
    }
    log::info!("Account xpub: {xpub}");

    // Ownership proofs, checked against the functional core: the device path
    // (seed read once, account keys cached) must agree byte for byte with the
    // seed-derived reference.
    let secp = Secp256k1::new();
    let seed = mnemonic.to_seed("");
    let commit = commitment(COORDINATOR);

    let path = [84 | H, H, H, 1, 0];
    let proof = expect_ok(
        &mut engine,
        CMD_GET_OWNERSHIP_PROOF,
        &ownership_request(&token, &path, &commit),
    );
    let expected = wallet_rpc_core::slip19::ownership_proof(
        &secp,
        &seed,
        Network::Bitcoin,
        &path,
        &commit,
        true,
    )
    .unwrap();
    assert_eq!(proof, expected, "segwit ownership proof matches functional core");

    let tr_path = [86 | H, H, H, 1, 0];
    let tr_proof = expect_ok(
        &mut engine,
        CMD_GET_OWNERSHIP_PROOF,
        &ownership_request(&token, &tr_path, &commit),
    );
    let tr_expected = wallet_rpc_core::slip19::ownership_proof_for(
        &secp,
        &seed,
        Network::Bitcoin,
        ScriptType::P2tr,
        &tr_path,
        &commit,
        true,
    )
    .unwrap();
    assert_eq!(tr_proof, tr_expected, "taproot ownership proof matches functional core");

    // Sign a conforming coinjoin round (taproot key spend).
    let psbt = fixture_psbt(&secp, &seed);
    let mut payload = token.clone();
    payload.extend_from_slice(&psbt.serialize());
    let signed = expect_ok(&mut engine, CMD_SIGN_COINJOIN, &payload);
    let signed_psbt = Psbt::deserialize(&signed).expect("parse signed PSBT");
    let witness = signed_psbt.inputs[0].final_script_witness.as_ref().expect("our input signed");
    assert_eq!(witness.len(), 1, "taproot key spend has a single witness element");
    assert_eq!(witness.nth(0).unwrap().len(), 64, "schnorr signature length");
    assert_eq!(
        signed_psbt.inputs[1].final_script_witness.is_none(),
        true,
        "foreign input untouched"
    );

    // A proof committing to a foreign coordinator must be rejected.
    let evil = commitment(b"EvilCoordinator");
    let resp = engine
        .process_frame(&frame(CMD_GET_OWNERSHIP_PROOF, &ownership_request(&token, &path, &evil)));
    assert_eq!(resp[2], STATUS_ERR_POLICY, "foreign coordinator rejected");

    // A guessed token must not reach the session.
    let mut wrong = token.clone();
    wrong[TOKEN_LEN - 1] ^= 1;
    let resp = engine
        .process_frame(&frame(CMD_GET_OWNERSHIP_PROOF, &ownership_request(&wrong, &path, &commit)));
    assert_eq!(resp[2], wallet_rpc_core::protocol::STATUS_ERR_NO_SESSION, "wrong token rejected");

    log::info!("wallet-rpc end-to-end test completed");
    // The log server is async and pass() shuts the kernel down immediately, so
    // give the final lines a moment to flush before exiting.
    thread::sleep(Duration::from_millis(500));
    pass();
}

fn frame(cmd: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![PROTOCOL_VERSION, cmd];
    f.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    f.extend_from_slice(payload);
    f
}

fn expect_ok(engine: &mut Engine<SecurityBackend>, cmd: u8, payload: &[u8]) -> Vec<u8> {
    let resp = engine.process_frame(&frame(cmd, payload));
    assert_eq!(resp[2], STATUS_OK, "command status");
    let len = u32::from_le_bytes(resp[3..7].try_into().unwrap()) as usize;
    assert_eq!(resp.len(), 7 + len, "response length");
    resp[7..].to_vec()
}

fn commitment(coordinator: &[u8]) -> Vec<u8> {
    let mut c = vec![coordinator.len() as u8];
    c.extend_from_slice(coordinator);
    c.extend_from_slice(&[0xab; 32]);
    c
}

fn ownership_request(token: &[u8], path: &[u32], commitment: &[u8]) -> Vec<u8> {
    let mut payload = token.to_vec();
    payload.push(path.len() as u8);
    for i in path {
        payload.extend_from_slice(&i.to_le_bytes());
    }
    payload.extend_from_slice(&(commitment.len() as u16).to_le_bytes());
    payload.extend_from_slice(commitment);
    payload
}

fn policy_bytes() -> Vec<u8> {
    Policy {
        network: Network::Bitcoin,
        account: 0,
        coordinator_id: COORDINATOR.to_vec(),
        fee_budget_sats: 10_000,
        max_rounds: 5,
        valid_for_secs: 3600,
    }
    .serialize()
}

/// Taproot coinjoin round: our BIP-86 input, a foreign input, our change output
/// and a foreign output. Every input carries a witness utxo, as a WabiSabi
/// coordinator sends.
fn fixture_psbt(secp: &Secp256k1<All>, seed: &[u8]) -> Psbt {
    let master = Xpriv::new_master(Network::Bitcoin, seed).unwrap();
    let fingerprint = master.fingerprint(secp);
    let derive = |path: &[u32]| {
        let derivation: DerivationPath =
            path.iter().map(|&i| ChildNumber::from(i)).collect::<Vec<_>>().into();
        let xpriv = master.derive_priv(secp, &derivation).unwrap();
        let spk = wallet_rpc_core::slip19::script_pubkey(secp, &xpriv, ScriptType::P2tr);
        (xpriv, spk, derivation)
    };
    let (in_xpriv, in_spk, in_path) = derive(&[86 | H, H, H, 0, 0]);
    let (out_xpriv, out_spk, out_path) = derive(&[86 | H, H, H, 1, 0]);

    let foreign_path: DerivationPath = [84 | H, H, 99 | H, 0, 0]
        .iter()
        .map(|&i| ChildNumber::from(i))
        .collect::<Vec<_>>()
        .into();
    let foreign_pk = CompressedPublicKey(
        master.derive_priv(secp, &foreign_path).unwrap().private_key.public_key(secp),
    );
    let foreign_spk = ScriptBuf::new_p2wpkh(&foreign_pk.wpubkey_hash());

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([1; 32]), 0),
                sequence: Sequence::MAX,
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([2; 32]), 1),
                sequence: Sequence::MAX,
                ..Default::default()
            },
        ],
        output: vec![
            TxOut { value: Amount::from_sat(95_000), script_pubkey: out_spk },
            TxOut { value: Amount::from_sat(50_000), script_pubkey: foreign_spk.clone() },
        ],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo =
        Some(TxOut { value: Amount::from_sat(100_000), script_pubkey: in_spk });
    psbt.inputs[0].tap_key_origins.insert(
        xonly(secp, &in_xpriv),
        (vec![], (fingerprint, in_path)),
    );
    psbt.inputs[1].witness_utxo =
        Some(TxOut { value: Amount::from_sat(60_000), script_pubkey: foreign_spk });
    psbt.outputs[0]
        .tap_key_origins
        .insert(xonly(secp, &out_xpriv), (vec![], (fingerprint, out_path)));
    psbt
}

fn xonly(
    secp: &Secp256k1<All>,
    xpriv: &Xpriv,
) -> ngwallet::bdk_wallet::bitcoin::secp256k1::XOnlyPublicKey {
    use ngwallet::bdk_wallet::bitcoin::key::Keypair;
    let keypair = Keypair::from_secret_key(secp, &xpriv.private_key);
    let (xonly, _) = ngwallet::bdk_wallet::bitcoin::secp256k1::XOnlyPublicKey::from_keypair(&keypair);
    xonly
}
