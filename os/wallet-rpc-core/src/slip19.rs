// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! SLIP-0019 proof of ownership (P2WPKH), Trezor-compatible.
//!
//! `proof = proofBody || bip322Signature` where
//! `proofBody = 0x534c0019 || flags || varint(n) || ownership_id * n` and the
//! signed digest is `SHA256(proofBody || varint(len(spk)) || spk ||
//! varint(len(commitment)) || commitment)`. The ownership id is
//! `HMAC-SHA256(k, spk)` with `k` the SLIP-0021 node
//! `m/"SLIP-0019"/"Ownership identification key"` of the BIP-0039 seed.
//!
//! Purely functional: seed in, proof out. No KeyOS server dependencies.

use ngwallet::bdk_wallet::bitcoin::{
    bip32::{ChildNumber, DerivationPath, Xpriv},
    hashes::{hmac::HmacEngine, sha256, sha512, Hash, HashEngine, Hmac},
    secp256k1::{All, Message, Secp256k1},
    CompressedPublicKey, Network,
};

pub const FLAG_USER_CONFIRMATION: u8 = 0x01;
const VERSION_MAGIC: [u8; 4] = [0x53, 0x4c, 0x00, 0x19];

#[derive(Debug, thiserror::Error)]
pub enum Slip19Error {
    #[error("bip32 derivation failed: {0}")]
    Bip32(#[from] ngwallet::bdk_wallet::bitcoin::bip32::Error),
}

fn push_varint(value: u64, out: &mut Vec<u8>) {
    match value {
        0..=0xfc => out.push(value as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
}

/// SLIP-0021 node derivation. Master node from the BIP-0039 seed, then one
/// child step per label. Returns the node's 32-byte key.
fn slip21_key(seed: &[u8], labels: &[&[u8]]) -> [u8; 32] {
    let mut node = hmac_sha512(b"Symmetric key seed", seed);
    for label in labels {
        let mut msg = Vec::with_capacity(1 + label.len());
        msg.push(0x00);
        msg.extend_from_slice(label);
        node = hmac_sha512(&node[..32], &msg);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&node[32..]);
    key
}

fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut engine = HmacEngine::<sha512::Hash>::new(key);
    engine.input(msg);
    Hmac::<sha512::Hash>::from_engine(engine).to_byte_array()
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut engine = HmacEngine::<sha256::Hash>::new(key);
    engine.input(msg);
    Hmac::<sha256::Hash>::from_engine(engine).to_byte_array()
}

/// The device's ownership id for a scriptPubKey (SLIP-0019 § Ownership identifier).
pub fn ownership_id(seed: &[u8], script_pubkey: &[u8]) -> [u8; 32] {
    let key = slip21_key(seed, &[b"SLIP-0019", b"Ownership identification key"]);
    hmac_sha256(&key, script_pubkey)
}

/// Generate a SLIP-0019 ownership proof for the P2WPKH key at `path`.
pub fn ownership_proof(
    secp: &Secp256k1<All>,
    seed: &[u8],
    network: Network,
    path: &[u32],
    commitment_data: &[u8],
    user_confirmation: bool,
) -> Result<Vec<u8>, Slip19Error> {
    let derivation: DerivationPath =
        path.iter().map(|&i| ChildNumber::from(i)).collect::<Vec<_>>().into();
    let xpriv = Xpriv::new_master(network, seed)?.derive_priv(secp, &derivation)?;
    let pubkey = CompressedPublicKey(xpriv.private_key.public_key(secp));

    // P2WPKH scriptPubKey: OP_0 PUSH20 <hash160(pubkey)>
    let mut spk = Vec::with_capacity(22);
    spk.push(0x00);
    spk.push(0x14);
    spk.extend_from_slice(pubkey.wpubkey_hash().as_byte_array());

    // Proof body
    let mut proof = Vec::new();
    proof.extend_from_slice(&VERSION_MAGIC);
    proof.push(if user_confirmation { FLAG_USER_CONFIRMATION } else { 0 });
    push_varint(1, &mut proof);
    proof.extend_from_slice(&ownership_id(seed, &spk));

    // Sighash = SHA256(proofBody || proofFooter)
    let mut preimage = proof.clone();
    push_varint(spk.len() as u64, &mut preimage);
    preimage.extend_from_slice(&spk);
    push_varint(commitment_data.len() as u64, &mut preimage);
    preimage.extend_from_slice(commitment_data);
    let sighash = sha256::Hash::hash(&preimage);

    // BIP-322 "simple" signature for P2WPKH: empty scriptSig + standard witness.
    let signature =
        secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &xpriv.private_key);
    let mut der = signature.serialize_der().to_vec();
    der.push(0x01); // SIGHASH_ALL

    proof.push(0x00); // empty scriptSig
    push_varint(2, &mut proof); // witness stack: [signature, pubkey]
    push_varint(der.len() as u64, &mut proof);
    proof.extend_from_slice(&der);
    push_varint(33, &mut proof);
    proof.extend_from_slice(&pubkey.to_bytes());

    Ok(proof)
}

#[cfg(test)]
mod tests {
    use ngwallet::bdk_wallet::keys::bip39::Mnemonic;

    use super::*;

    // SLIP-0019 spec P2WPKH test vector ("all all ..." seed, m/84'/0'/0'/1/0, empty commitment).
    const H: u32 = 0x8000_0000;

    fn test_seed() -> Vec<u8> {
        Mnemonic::parse("all all all all all all all all all all all all")
            .unwrap()
            .to_seed("")
            .to_vec()
    }

    #[test]
    fn spec_ownership_id() {
        let spk = hex("0014b2f771c370ccf219cd3059cda92bdf7f00cf2103");
        assert_eq!(
            ownership_id(&test_seed(), &spk).to_vec(),
            hex("a122407efc198211c81af4450f40b235d54775efd934d16b9e31c6ce9bad5707"),
        );
    }

    #[test]
    fn spec_p2wpkh_proof() {
        let secp = Secp256k1::new();
        let proof = ownership_proof(
            &secp,
            &test_seed(),
            Network::Bitcoin,
            &[84 | H, H, H, 1, 0],
            &[],
            false,
        )
        .unwrap();
        assert_eq!(
            proof,
            hex(
                "534c00190001a122407efc198211c81af4450f40b235d54775efd934d16b9e31c6ce9bad5707\
                 0002483045022100c0dc28bb563fc5fea76cacff75dba9cb4122412faae01937cdebccfb065f9a70\
                 02202e980bfbd8a434a7fc4cd2ca49da476ce98ca097437f8159b1a386b41fcdfac50121032ef683\
                 18c8f6aaa0adec0199c69901f0db7d3485eb38d9ad235221dc3d61154b"
            ),
        );
    }

    #[test]
    fn user_confirmation_flag_set() {
        let secp = Secp256k1::new();
        let proof = ownership_proof(
            &secp,
            &test_seed(),
            Network::Bitcoin,
            &[84 | H, H, H, 1, 0],
            b"commitment",
            true,
        )
        .unwrap();
        assert_eq!(proof[4], FLAG_USER_CONFIRMATION);
        // commitment data must change the signature vs the spec vector
        assert_ne!(&proof[38..], &hex("0002483045022100c0dc28bb")[..]);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
}
