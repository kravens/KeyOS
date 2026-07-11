// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

pub mod api;
pub mod error;
mod implementation;
pub mod messages;

// Re-export the host-independent core so downstream users (and the app) have a
// single `wallet_rpc::…` surface.
pub use wallet_rpc_core::{coinjoin, frames, protocol, slip19};

pub fn listen() { server::listen(implementation::WalletRpcServer::new().unwrap()) }
