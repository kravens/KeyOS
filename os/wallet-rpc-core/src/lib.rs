// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Host-independent coinjoin remote-signing core for Passport Prime.
//!
//! Everything here is functional over its inputs (seeds, policies, PSBTs, byte
//! frames) with no KeyOS server, USB, or GUI dependency. The `wallet-rpc`
//! server crate wraps this with the USB HID transport, the security-server seed
//! source, and the on-device approval UI.

pub mod coinjoin;
pub mod frames;
pub mod protocol;
pub mod slip19;
