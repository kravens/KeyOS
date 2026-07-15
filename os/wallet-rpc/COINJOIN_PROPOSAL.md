# Coinjoin on Passport Prime — QuantumLink protocol-extension proposal

For the Foundation dev/QnA team. A community proposal to let Passport Prime act
as an unattended coinjoin signer for Wasabi Wallet (WabiSabi), consistent with
the SDK's own listed use case ("keep secrets offline, sign quickly via
QuantumLink for interactive protocols like Lightning, Nostr, Ark, swaps, and
**Coinjoins**").

- Author: Kevin Ravensberg (coinjoin.nl coordinator) · GPLv3
- Firmware branch: https://github.com/kravens/KeyOS/tree/feature/passport-coinjoin
- Wasabi branch: https://github.com/kravens/WalletWasabi/tree/feature/passport-coinjoin

## TL;DR — the ask

Coinjoin over QuantumLink needs **two message types that don't exist yet** in
`foundation_api` / `quantum_link::messages`. PSBT signing we can already do with
your existing `PublishPsbt` / `SubscribeSignPsbt`. The two missing pieces:

1. **`AuthorizeCoinjoin`** — a one-time, on-device-approved coinjoin session policy.
2. **`GetOwnershipProof`** — a SLIP-0019 ownership proof for one input (this is a
   BIP-322-style signature, *not* a PSBT, so `SignPsbt` can't express it).

We have the complete on-device logic for both already implemented and tested
(`wallet-rpc-core`, 29 unit tests incl. the SLIP-0019 spec vector). It's
transport-agnostic and drops straight in behind these messages. **Would you
consider adding them to the QuantumLink protocol?** Alternatively, a dev unit
lets us prototype the whole thing while you evaluate.

## Why this shape (what we found in the SDK docs)

- **USB HID for third-party apps is 🚧 Coming**, so an app can't open its own USB
  data channel today.
- **QuantumLink is the blessed interactive transport** (you name coinjoins
  explicitly), but its message set is a fixed, curated enum in `foundation_api`
  — there's no generic app-to-desktop channel, so a custom protocol can only
  ride QuantumLink if the messages exist in that enum.

Hence a protocol proposal rather than a standalone app. This is a small, bounded
addition to a protocol you own, not a request to bless a large custom surface.

## Background: what a coinjoin signer must do

WabiSabi rounds have three signer touchpoints, repeated every round with tight
phase deadlines (so they must be unattended after a one-time approval):

1. **Ownership proof** at input registration — a SLIP-0019 proof over the
   coordinator's commitment data, proving we own an input without revealing which
   wallet. *(New message needed.)*
2. **Sign** the round's coinjoin transaction (our inputs only; foreign inputs are
   left for their owners). *(Existing `PublishPsbt`/`SignPsbt` covers this.)*
3. This repeats for many rounds under one user authorization. *(New `AuthorizeCoinjoin`.)*

## Proposed message 1 — `AuthorizeCoinjoin`

One-time policy the user reviews and approves on the trusted display. After
approval, conforming rounds sign without further prompts; the device caches the
derived key for the session (see security model), so seed retrieval prompts the
user exactly once. Non-conforming requests are rejected outright, never escalated.

Policy fields (our current wire form; adapt to your serialization):

```
network            u8      (0=main, 1=test)
account            u32     BIP-84 account index
coordinator_id     string  committed into ownership proofs
max_fee_contribution  u64  sats the wallet may lose per round (mining+coord share)
max_rounds         u16     session round budget
valid_for_secs     u32     session lifetime
```

Returns a `session_id`. The device enforces, per round (implemented in
`wallet_rpc_core::coinjoin::check_and_sign`):

- **Self-spend only** — every input/output claimed as ours must re-derive from
  the seed to exactly its scriptPubKey; a lying host gains nothing.
- **Account scope** — our keys must sit under the authorized account.
- **Bounded loss** — `sum(our inputs) − sum(our outputs) ≤ max_fee_contribution`;
  only outputs paying back into the account count as credit.
- **Session limits** — stops after `max_rounds` or expiry; RAM-only, cleared on reboot.

## Proposed message 2 — `GetOwnershipProof`

Request: `{ session_id, derivation_path, commitment_data }`.
Response: the serialized SLIP-0019 proof.

Format (Trezor-compatible, verified byte-for-byte against the SLIP-0019 test
vector in our tests): `proof = proofBody || bip322Sig`, where
`proofBody = 0x534c0019 || flags || varint(n) || ownership_id*n`, the ownership
id is `HMAC-SHA256(SLIP-21_node(seed, "SLIP-0019"/"Ownership identification key"),
scriptPubKey)`, and the signed digest is
`SHA256(proofBody || varint(len(spk))||spk || varint(len(cd))||cd)`. Segwit v0
(P2WPKH) in this version; taproot is a follow-up.

The device only signs a commitment that opens with the **authorized coordinator
id** — binding the proof to the session's coordinator.

## Signing — reuse your existing messages

The round signature is an ordinary PSBT sign of our inputs. We can drive that
through `PublishPsbt` / `SubscribeSignPsbt` as-is, applying the same policy
conformance check before signing. No new message needed here.

## Security model

- **Seed never leaves the device.** Over QuantumLink we exchange paths, a policy,
  PSBTs, commitment data; back come xpubs, proofs, signatures. Keys are derived
  on-device.
- **One trusted-display approval per session.** We retrieve the seed once at
  `AuthorizeCoinjoin` (right after the user approves), cache it for the session
  (`Zeroizing`, cleared on drop/reboot), and serve all rounds from the cache — so
  seed retrieval prompts the user once, not per round. Happy to instead use a
  per-session derived key if you'd prefer the raw seed never be cached.
- **Trusted-display approval** goes through KeyOS UI, not our app's UI.
- Malformed input returns a status code, never panics (KeyOS "avoid panicking").

## What's built and how to verify

```
git clone -b feature/passport-coinjoin https://github.com/kravens/KeyOS && cd KeyOS
cargo test -p wallet-rpc-core   # 29/29, incl. SLIP-0019 spec vector
```

`os/wallet-rpc-core` is the transport-agnostic logic (protocol, SLIP-0019,
coinjoin policy + signing, framing). Whatever transport you prefer — new
QuantumLink messages, or the USB app capability when it ships — this logic sits
behind it unchanged. The Wasabi side is implemented too (currently a USB client;
would become a desktop QuantumLink client).

## Questions for you

1. Would you add `AuthorizeCoinjoin` + `GetOwnershipProof` to
   `foundation_api` / QuantumLink? We're happy to open a PR against KeyOS.
2. Is there a **desktop QuantumLink client** (Rust/C#) we can use from Wasabi, or
   is QuantumLink currently Envoy/mobile-only? *(This is our biggest open unknown.)*
3. Does the **session-cached-seed** approach satisfy your seed-handling rules, or
   would you prefer a per-session derived key?
4. Could we get a **dev unit** to prototype on, and your **security-review
   checklist** (the docs ask key-touching apps to request it before shipping)?
