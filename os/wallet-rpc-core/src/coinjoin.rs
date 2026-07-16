// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Coinjoin session policy and policy-enforced PSBT signing.
//!
//! A session is approved once by the user on the device (via `AuthorizeCoinjoin`).
//! After that, ownership proofs and signatures for rounds that conform to the
//! policy are issued without further interaction; anything non-conforming is
//! rejected outright (never escalated mid-round — WabiSabi phase deadlines
//! don't allow waiting for a human).
//!
//! Purely functional over (seed, policy, psbt) — no KeyOS server dependencies.

use std::time::Instant;

use ngwallet::bdk_wallet::bitcoin::{
    bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv},
    ecdsa,
    hashes::Hash,
    psbt::Psbt,
    secp256k1::{All, Message, Secp256k1},
    sighash::SighashCache,
    Amount, CompressedPublicKey, EcdsaSighashType, Network, ScriptBuf, Witness,
};
use zeroize::Zeroizing;

/// Purpose level of the BIP-84 account the policy covers.
const PURPOSE: u32 = 84;
/// BIP-86 taproot purpose — proofs only for now; round signing stays segwit v0.
const PURPOSE_TR: u32 = 86;
const HARDENED: u32 = 0x8000_0000;

#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    pub network: Network,
    /// BIP-84 account index (unhardened notation).
    pub account: u32,
    /// Coordinator identifier, as committed into ownership proofs (ASCII).
    pub coordinator_id: Vec<u8>,
    /// Maximum sats this wallet may lose in one round (mining fee share +
    /// coordination fee): sum(our inputs) - sum(our outputs) per round.
    pub max_fee_contribution: u64,
    /// Maximum number of rounds this session may sign.
    pub max_rounds: u16,
    /// Session lifetime in seconds from approval.
    pub valid_for_secs: u32,
}

impl Policy {
    /// Wire format, little-endian:
    /// `[network u8 (0=main,1=test)][account u32][coord_len u8][coord bytes]`
    /// `[max_fee_contribution u64][max_rounds u16][valid_for_secs u32]`
    pub fn parse(payload: &[u8]) -> Option<(Policy, usize)> {
        let coord_len = *payload.get(5)? as usize;
        let total = 6 + coord_len + 8 + 2 + 4;
        if payload.len() < total {
            return None;
        }
        let network = match payload[0] {
            0 => Network::Bitcoin,
            1 => Network::Testnet,
            _ => return None,
        };
        let account = u32::from_le_bytes(payload[1..5].try_into().ok()?);
        let coordinator_id = payload[6..6 + coord_len].to_vec();
        let rest = &payload[6 + coord_len..];
        Some((
            Policy {
                network,
                account,
                coordinator_id,
                max_fee_contribution: u64::from_le_bytes(rest[..8].try_into().ok()?),
                max_rounds: u16::from_le_bytes(rest[8..10].try_into().ok()?),
                valid_for_secs: u32::from_le_bytes(rest[10..14].try_into().ok()?),
            },
            total,
        ))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(match self.network {
            Network::Bitcoin => 0,
            _ => 1,
        });
        out.extend_from_slice(&self.account.to_le_bytes());
        out.push(self.coordinator_id.len() as u8);
        out.extend_from_slice(&self.coordinator_id);
        out.extend_from_slice(&self.max_fee_contribution.to_le_bytes());
        out.extend_from_slice(&self.max_rounds.to_le_bytes());
        out.extend_from_slice(&self.valid_for_secs.to_le_bytes());
        out
    }

    fn coin_type(&self) -> u32 {
        match self.network {
            Network::Bitcoin => 0,
            _ => 1,
        }
    }

    /// `m/84'/coin'/account'` prefix this policy covers.
    fn account_prefix(&self) -> [u32; 3] {
        [PURPOSE | HARDENED, self.coin_type() | HARDENED, self.account | HARDENED]
    }

    /// A derivation path is in scope iff it is exactly
    /// `purpose'/coin'/account'/change/index` with the policy's coin + account,
    /// purpose 84' (segwit v0) or 86' (taproot), and change ∈ {0, 1}.
    pub fn path_in_scope(&self, path: &[u32]) -> bool {
        let prefix = self.account_prefix();
        path.len() == 5
            && (path[0] == (PURPOSE | HARDENED) || path[0] == (PURPOSE_TR | HARDENED))
            && path[1..3] == prefix[1..3]
            && (path[3] == 0 || path[3] == 1)
            && path[4] < HARDENED
    }
}

#[derive(Debug)]
pub struct Session {
    pub id: u32,
    pub policy: Policy,
    pub authorized_at: Instant,
    pub rounds_used: u16,
    /// The BIP-39 seed, retrieved once at authorization and cached for the
    /// session. Keeping it here means ownership proofs and signatures don't
    /// re-fetch the seed each round — on Passport that would prompt the user on
    /// the trusted display every round (secure-element seed retrieval is gated
    /// per-op); with the session cache there is exactly one prompt, at authorize.
    /// Zeroized when the session is dropped (revoke / expiry / reboot).
    pub seed: Zeroizing<Vec<u8>>,
}

impl Session {
    pub fn is_expired(&self) -> bool {
        self.authorized_at.elapsed().as_secs() > self.policy.valid_for_secs as u64
            || self.rounds_used >= self.policy.max_rounds
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum CoinjoinError {
    #[error("malformed PSBT")]
    MalformedPsbt,
    #[error("session expired or round budget exhausted")]
    SessionExpired,
    #[error("input {0} claims our key but the derivation is out of policy scope")]
    InputOutOfScope(usize),
    #[error("input {0} derivation does not match its scriptPubKey")]
    InputKeyMismatch(usize),
    #[error("input {0} is missing its witness utxo")]
    MissingWitnessUtxo(usize),
    #[error("output {0} derivation does not match its scriptPubKey")]
    OutputKeyMismatch(usize),
    #[error("no inputs of ours in this transaction")]
    NothingToSign,
    #[error("fee contribution {actual} exceeds the authorized maximum {max}")]
    FeeExceeded { actual: u64, max: u64 },
    #[error("bip32 derivation failed")]
    Derivation,
}

/// Outcome of a conforming signing run.
#[derive(Debug)]
pub struct SignedRound {
    pub psbt_bytes: Vec<u8>,
    pub our_inputs: Vec<usize>,
}

/// Verify the round PSBT against the policy and sign our P2WPKH inputs.
///
/// "Ours" is decided by the BIP-32 derivations embedded in the PSBT: an entry
/// with our fingerprint must re-derive from our seed to exactly the input's
/// scriptPubKey (a lying host gains nothing — wrong paths either fail the
/// pubkey check or derive a script that isn't in the transaction).
/// The self-spend guarantee is the fee bound: only outputs that provably pay
/// back to keys under the policy account count as credit, so
/// `our inputs - our outputs ≤ max_fee_contribution` caps what the wallet can
/// lose no matter what the rest of the transaction looks like.
pub fn check_and_sign(
    secp: &Secp256k1<All>,
    session: &Session,
    psbt_bytes: &[u8],
) -> Result<SignedRound, CoinjoinError> {
    if session.is_expired() {
        return Err(CoinjoinError::SessionExpired);
    }
    let policy = &session.policy;

    let mut psbt = Psbt::deserialize(psbt_bytes).map_err(|_| CoinjoinError::MalformedPsbt)?;
    let master =
        Xpriv::new_master(policy.network, &session.seed).map_err(|_| CoinjoinError::Derivation)?;
    let fingerprint = master.fingerprint(secp);

    // Classify inputs.
    let mut our_inputs: Vec<(usize, Xpriv, CompressedPublicKey, ScriptBuf, Amount)> = Vec::new();
    let mut our_input_sum = Amount::ZERO;
    for (index, input) in psbt.inputs.iter().enumerate() {
        let Some((path, _)) = ours_in_derivation(&input.bip32_derivation, fingerprint) else {
            continue;
        };
        if !policy.path_in_scope(&path) {
            return Err(CoinjoinError::InputOutOfScope(index));
        }
        let utxo = input.witness_utxo.as_ref().ok_or(CoinjoinError::MissingWitnessUtxo(index))?;
        let (xpriv, pubkey, spk) =
            derive_p2wpkh(secp, &master, &path).ok_or(CoinjoinError::Derivation)?;
        if utxo.script_pubkey != spk {
            return Err(CoinjoinError::InputKeyMismatch(index));
        }
        our_input_sum += utxo.value;
        our_inputs.push((index, xpriv, pubkey, spk, utxo.value));
    }
    if our_inputs.is_empty() {
        return Err(CoinjoinError::NothingToSign);
    }

    // Credit: outputs that provably pay back into the policy account.
    let mut our_output_sum = Amount::ZERO;
    for (index, output) in psbt.outputs.iter().enumerate() {
        let Some((path, _)) = ours_in_derivation(&output.bip32_derivation, fingerprint) else {
            continue;
        };
        if !policy.path_in_scope(&path) {
            continue; // out-of-scope claim: simply not credited
        }
        let (_, _, spk) = derive_p2wpkh(secp, &master, &path).ok_or(CoinjoinError::Derivation)?;
        let tx_out =
            psbt.unsigned_tx.output.get(index).ok_or(CoinjoinError::MalformedPsbt)?;
        if tx_out.script_pubkey != spk {
            return Err(CoinjoinError::OutputKeyMismatch(index));
        }
        our_output_sum += tx_out.value;
    }

    let contribution = our_input_sum
        .to_sat()
        .saturating_sub(our_output_sum.to_sat());
    if contribution > policy.max_fee_contribution {
        return Err(CoinjoinError::FeeExceeded {
            actual: contribution,
            max: policy.max_fee_contribution,
        });
    }

    // Sign our inputs (BIP-143 P2WPKH, SIGHASH_ALL).
    let tx = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&tx);
    let mut signed_indexes = Vec::with_capacity(our_inputs.len());
    for (index, xpriv, pubkey, spk, amount) in our_inputs {
        let sighash = cache
            .p2wpkh_signature_hash(index, &spk, amount, EcdsaSighashType::All)
            .map_err(|_| CoinjoinError::MalformedPsbt)?;
        let signature = ecdsa::Signature {
            signature: secp.sign_ecdsa(
                &Message::from_digest(sighash.to_byte_array()),
                &xpriv.private_key,
            ),
            sighash_type: EcdsaSighashType::All,
        };
        psbt.inputs[index].final_script_witness = Some(Witness::p2wpkh(&signature, &pubkey.0));
        signed_indexes.push(index);
    }

    Ok(SignedRound { psbt_bytes: psbt.serialize(), our_inputs: signed_indexes })
}

/// First derivation entry carrying our fingerprint, as raw path indexes.
fn ours_in_derivation<K>(
    map: &std::collections::BTreeMap<K, (Fingerprint, DerivationPath)>,
    fingerprint: Fingerprint,
) -> Option<(Vec<u32>, ())> {
    map.values().find(|(fp, _)| *fp == fingerprint).map(|(_, path)| {
        (path.into_iter().map(|child| u32::from(*child)).collect(), ())
    })
}

fn derive_p2wpkh(
    secp: &Secp256k1<All>,
    master: &Xpriv,
    path: &[u32],
) -> Option<(Xpriv, CompressedPublicKey, ScriptBuf)> {
    let derivation: DerivationPath =
        path.iter().map(|&i| ChildNumber::from(i)).collect::<Vec<_>>().into();
    let xpriv = master.derive_priv(secp, &derivation).ok()?;
    let pubkey = CompressedPublicKey(xpriv.private_key.public_key(secp));
    let spk = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash());
    Some((xpriv, pubkey, spk))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ngwallet::bdk_wallet::{
        bitcoin::{
            absolute::LockTime, hashes::Hash, transaction::Version, OutPoint, Sequence,
            Transaction, TxIn, TxOut, Txid,
        },
        keys::bip39::Mnemonic,
    };

    use super::*;

    const H: u32 = HARDENED;

    fn seed() -> Vec<u8> {
        Mnemonic::parse("all all all all all all all all all all all all")
            .unwrap()
            .to_seed("")
            .to_vec()
    }

    fn policy() -> Policy {
        Policy {
            network: Network::Bitcoin,
            account: 0,
            coordinator_id: b"CoinJoinCoordinatorIdentifier".to_vec(),
            max_fee_contribution: 10_000,
            max_rounds: 5,
            valid_for_secs: 3600,
        }
    }

    fn session() -> Session {
        Session {
            id: 1,
            policy: policy(),
            authorized_at: Instant::now(),
            rounds_used: 0,
            seed: Zeroizing::new(seed()),
        }
    }

    /// Coinjoin-shaped PSBT: our input (m/84'/0'/0'/0/0), a foreign input,
    /// our output (m/84'/0'/0'/1/0) and a foreign output.
    fn fixture_psbt(
        secp: &Secp256k1<All>,
        our_in: u64,
        our_out: u64,
        our_out_path: &[u32],
    ) -> Psbt {
        let master = Xpriv::new_master(Network::Bitcoin, &seed()).unwrap();
        let fingerprint = master.fingerprint(secp);
        let (_, in_pk, in_spk) = derive_p2wpkh(secp, &master, &[84 | H, H, H, 0, 0]).unwrap();
        let (_, out_pk, out_spk) = derive_p2wpkh(secp, &master, our_out_path).unwrap();

        let foreign_spk = ScriptBuf::new_p2wpkh(
            &CompressedPublicKey::from_slice(
                &hex("032ef68318c8f6aaa0adec0199c69901f0db7d3485eb38d9ad235221dc3d61154b"),
            )
            .unwrap()
            .wpubkey_hash(),
        );

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
                TxOut { value: Amount::from_sat(our_out), script_pubkey: out_spk },
                TxOut { value: Amount::from_sat(50_000), script_pubkey: foreign_spk.clone() },
            ],
        };

        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        psbt.inputs[0].witness_utxo =
            Some(TxOut { value: Amount::from_sat(our_in), script_pubkey: in_spk });
        psbt.inputs[0].bip32_derivation.insert(
            in_pk.0,
            (fingerprint, vec![ChildNumber::from(84 | H), ChildNumber::from(H), ChildNumber::from(H), ChildNumber::from(0), ChildNumber::from(0)].into()),
        );
        psbt.inputs[1].witness_utxo =
            Some(TxOut { value: Amount::from_sat(60_000), script_pubkey: foreign_spk });

        psbt.outputs[0].bip32_derivation.insert(
            out_pk.0,
            (
                fingerprint,
                our_out_path.iter().map(|&i| ChildNumber::from(i)).collect::<Vec<_>>().into(),
            ),
        );

        psbt
    }

    #[test]
    fn conforming_round_signs_our_input_only() {
        let secp = Secp256k1::new();
        let psbt = fixture_psbt(&secp, 100_000, 95_000, &[84 | H, H, H, 1, 0]);
        let signed = check_and_sign(&secp, &session(), &psbt.serialize()).unwrap();
        assert_eq!(signed.our_inputs, vec![0]);

        let out = Psbt::deserialize(&signed.psbt_bytes).unwrap();
        let witness = out.inputs[0].final_script_witness.as_ref().unwrap();
        assert_eq!(witness.len(), 2);
        assert!(out.inputs[1].final_script_witness.is_none(), "foreign input untouched");
    }

    #[test]
    fn fee_above_cap_rejected() {
        let secp = Secp256k1::new();
        // 100k in, 80k back: 20k contribution > 10k cap
        let psbt = fixture_psbt(&secp, 100_000, 80_000, &[84 | H, H, H, 1, 0]);
        let err = check_and_sign(&secp, &session(), &psbt.serialize()).unwrap_err();
        assert_eq!(err, CoinjoinError::FeeExceeded { actual: 20_000, max: 10_000 });
    }

    #[test]
    fn output_to_wrong_account_not_credited() {
        let secp = Secp256k1::new();
        // "our" output claims account 1 — out of policy scope, so not credited:
        // contribution = full 100k > cap.
        let psbt = fixture_psbt(&secp, 100_000, 95_000, &[84 | H, 1 | H, 1 | H, 1, 0]);
        let err = check_and_sign(&secp, &session(), &psbt.serialize()).unwrap_err();
        assert!(matches!(err, CoinjoinError::FeeExceeded { .. }));
    }

    #[test]
    fn lying_output_derivation_rejected() {
        let secp = Secp256k1::new();
        let mut psbt = fixture_psbt(&secp, 100_000, 95_000, &[84 | H, H, H, 1, 0]);
        // host lies: claims the foreign output pays to our change path
        let master = Xpriv::new_master(Network::Bitcoin, &seed()).unwrap();
        let fingerprint = master.fingerprint(&secp);
        let (_, pk, _) = derive_p2wpkh(&secp, &master, &[84 | H, H, H, 1, 5]).unwrap();
        psbt.outputs[1].bip32_derivation.insert(
            pk.0,
            (
                fingerprint,
                vec![ChildNumber::from(84 | H), ChildNumber::from(H), ChildNumber::from(H), ChildNumber::from(1), ChildNumber::from(5)].into(),
            ),
        );
        let err = check_and_sign(&secp, &session(), &psbt.serialize()).unwrap_err();
        assert_eq!(err, CoinjoinError::OutputKeyMismatch(1));
    }

    #[test]
    fn expired_session_rejected() {
        let secp = Secp256k1::new();
        let psbt = fixture_psbt(&secp, 100_000, 95_000, &[84 | H, H, H, 1, 0]);
        let mut session = session();
        session.authorized_at = Instant::now() - Duration::from_secs(7200);
        let err = check_and_sign(&secp, &session, &psbt.serialize()).unwrap_err();
        assert_eq!(err, CoinjoinError::SessionExpired);
    }

    #[test]
    fn round_budget_exhaustion_rejected() {
        let secp = Secp256k1::new();
        let psbt = fixture_psbt(&secp, 100_000, 95_000, &[84 | H, H, H, 1, 0]);
        let mut session = session();
        session.rounds_used = session.policy.max_rounds;
        let err = check_and_sign(&secp, &session, &psbt.serialize()).unwrap_err();
        assert_eq!(err, CoinjoinError::SessionExpired);
    }

    #[test]
    fn policy_wire_roundtrip() {
        let p = policy();
        let bytes = p.serialize();
        let (parsed, consumed) = Policy::parse(&bytes).unwrap();
        assert_eq!(parsed, p);
        assert_eq!(consumed, bytes.len());
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
}
