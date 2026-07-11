// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use server::{CheckedConn, CheckedPermissions, MessageAllowed};

use crate::messages::*;

#[macro_export]
macro_rules! use_api {
    () => {
        mod wallet_rpc_permissions {
            use wallet_rpc::messages::*;
            #[derive(Clone, Default, server::Permissions)]
            #[server_name = "os/wallet-rpc"]
            pub struct WalletRpcPermissions;
        }
        type WalletRpcApi = wallet_rpc::api::WalletRpcApi<wallet_rpc_permissions::WalletRpcPermissions>;
    };
}

#[derive(Default)]
pub struct WalletRpcApi<P: CheckedPermissions>(CheckedConn<P>);

impl<P: CheckedPermissions> WalletRpcApi<P> {
    pub fn process_rpc_frame(&mut self, frame: &[u8]) -> Vec<u8>
    where
        P: MessageAllowed<ProcessRpcFrame>,
    {
        self.0.send_archive(ProcessRpcFrame(frame.to_vec()))
    }
}
