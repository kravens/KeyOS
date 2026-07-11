// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

// === External messages ===

/// Process one wallet RPC request frame and return the response frame.
/// On hardware the USB receive thread sends this; in hosted/integration
/// tests the test client sends it directly, standing in for the USB host.
#[derive(Debug, Clone, server::Message, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[response(Vec<u8>)]
pub struct ProcessRpcFrame(pub Vec<u8>);
