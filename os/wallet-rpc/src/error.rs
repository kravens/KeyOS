// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

#[derive(Debug, thiserror::Error)]
pub enum WalletRpcError {
    #[error("USB error: {0:?}")]
    Usb(#[from] usb::error::UsbError),
}
