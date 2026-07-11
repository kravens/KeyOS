// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use ngwallet::bdk_wallet::bitcoin::{secp256k1::Secp256k1, Network};
use server::{ArchiveHandler, Server, ServerContext};
#[cfg(keyos)]
use usb::device::{
    api::{EndpointDirection, EndpointType},
    messages::{EndpointProperties, SetupPacketCallback},
};

use crate::{
    coinjoin::Policy,
    error::WalletRpcError,
    messages::ProcessRpcFrame,
    protocol::{Backend, Engine},
};

security::use_api!();
#[cfg(feature = "gui-approval")]
gui_server_api::use_api!();

#[cfg(keyos)]
usb::use_device_api!();

#[cfg(keyos)]
const USB_WALLET_IFCE_CLASS: u8 = 0x03; // Human Interface Device Class
#[cfg(keyos)]
const USB_WALLET_IFCE_SUBCLASS: u8 = 0x00;
#[cfg(keyos)]
const USB_WALLET_IFCE_PROTOCOL: u8 = 0x00;
#[cfg(keyos)]
const USB_WALLET_ENDPOINTS: [EndpointProperties; 2] = [
    EndpointProperties {
        ep_type: EndpointType::Interrupt,
        ep_direction: EndpointDirection::Out,
        max_packet_len: 64,
        interval: 5,
    },
    EndpointProperties {
        ep_type: EndpointType::Interrupt,
        ep_direction: EndpointDirection::In,
        max_packet_len: 64,
        interval: 5,
    },
];
#[cfg(keyos)]
const USB_WALLET_FUNC_DESCRIPTOR: [u8; 9] = [
    0x09, // bLength: 9
    0x21, // bDescriptorType: HID
    0x11, 0x01, // bcdHID: 1.11
    0x21, // bCountryCode: US
    0x01, // bNumDescriptors: 1
    0x22, // bDescriptorType: Report
    34, 0, // wDescriptorLength: 34
];
#[cfg(keyos)]
const USB_WALLET_REPORT_DESCRIPTOR: [u8; 34] = [
    0x06, 0x00, 0xFF, // Usage Page: Vendor Defined 0xFF00
    0x09, 0x01, // Usage: Vendor Usage 1
    0xA1, 0x01, // Collection: Application
    0x09, 0x20, // Usage: Input Report Data
    0x15, 0x00, // Logical Minimum: 0
    0x26, 0xFF, 0x00, // Logical Maximum: 255
    0x75, 0x08, // Report Size: 8 bits
    0x95, 64, // Report Count: 64 fields (must be same as EP max_packet_len)
    0x81, 0x02, // Input: Data | Variable | Absolute
    0x09, 0x21, // Usage: Output Report Data
    0x15, 0x00, // Logical Minimum: 0
    0x26, 0xFF, 0x00, // Logical Maximum: 255
    0x75, 0x08, // Report Size: 8 bits
    0x95, 64, // Report Count: 64 fields (must be same as EP max_packet_len)
    0x91, 0x02, // Output: Data | Variable | Absolute
    0xC0, // End Collection
];

#[cfg(keyos)]
#[derive(Default)]
pub(crate) struct SetupResponder {
    pub(crate) interface_num: u16,
}

#[cfg(keyos)]
impl server::ServerMessages for SetupResponder {
    const NAME: &'static str = "";

    fn messages() -> &'static [server::MessageDef<Self>]
    where
        Self: Sized,
    {
        use server::MessageId;
        &[(SetupPacketCallback::ID, server::handle_archive_message::<SetupPacketCallback, _>)]
    }
}
#[cfg(keyos)]
impl Server for SetupResponder {}

#[cfg(keyos)]
impl ArchiveHandler<SetupPacketCallback> for SetupResponder {
    fn handle(
        &mut self,
        SetupPacketCallback(msg): SetupPacketCallback,
        _sender: xous::PID,
        _context: &mut ServerContext<Self>,
    ) -> Option<Vec<u8>> {
        if msg.index == self.interface_num {
            if msg.request_type == 0x81 && msg.request == 0x06 {
                // HID GET_DESCRIPTOR
                if msg.value == 0x2200 {
                    Some(USB_WALLET_REPORT_DESCRIPTOR.to_vec())
                } else if msg.value == 0x2100 {
                    Some(USB_WALLET_FUNC_DESCRIPTOR.to_vec())
                } else {
                    None
                }
            } else if msg.request_type == 0x21 && msg.request == 0x0a {
                // HID SET_IDLE
                Some(vec![])
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[cfg(keyos)]
#[derive(Debug, Default, Clone)]
struct InternalPermissions;

#[cfg(keyos)]
impl server::CheckedPermissions for InternalPermissions {
    const NAME: &str = "os/wallet-rpc";
}

#[cfg(keyos)]
impl server::MessageAllowed<ProcessRpcFrame> for InternalPermissions {}

/// USB loop: reassemble request frames from HID reports, process them via the
/// server (synchronous response), split the response frame back into reports.
#[cfg(keyos)]
fn usb_thread(mut ep_out: UsbEmulatedEndpoint, mut ep_in: UsbEmulatedEndpoint) {
    let usb_api = UsbDeviceEmulation::default();
    let read_buffer = xous::map_memory(None, None, 0x1000, xous::MemoryFlags::W | xous::MemoryFlags::POPULATE)
        .expect("Could not allocate buffer");
    let mut api = crate::api::WalletRpcApi::<InternalPermissions>::default();
    let mut reassembler = crate::frames::Reassembler::default();

    loop {
        match ep_out.read_buf(read_buffer, 64) {
            Ok(pkt_len) => {
                let pkt = &read_buffer.as_slice::<u8>()[..pkt_len];
                let Some(frame) = reassembler.push_report(pkt) else {
                    continue;
                };
                let response = api.process_rpc_frame(&frame);
                for report in crate::frames::split_frame(&response) {
                    let mut write_buffer = xous::map_memory(None, None, 0x1000, xous::MemoryFlags::W)
                        .expect("Could not allocate buffer");
                    write_buffer.as_slice_mut()[..report.len()].copy_from_slice(&report);
                    if let Err(e) = ep_in.write_buf(write_buffer, report.len() as u16) {
                        log::error!("Error while writing to USB: {e:?}");
                        break;
                    }
                }
            }
            Err(e) => match e {
                usb::error::UsbError::HostDisconnected => {
                    usb_api.wait_for_connection().expect("Error waiting for connection");
                }
                _ => log::error!("Error while reading from USB: {e:?}"),
            },
        }
    }
}

/// Live backend: seed from the security server, approvals via a global GUI alert.
pub struct KeyOsBackend {
    security: Security,
    secp: Secp256k1<ngwallet::bdk_wallet::bitcoin::secp256k1::All>,
}

impl KeyOsBackend {
    fn new() -> Self { Self { security: Security::default(), secp: Secp256k1::new() } }
}

impl Backend for KeyOsBackend {
    fn firmware_version(&self) -> String { env!("CARGO_PKG_VERSION").to_string() }

    fn seed(&mut self) -> Option<Vec<u8>> {
        let entropy = match self.security.seed() {
            Ok(Some(seed)) => seed,
            Ok(None) => {
                log::warn!("No seed available");
                return None;
            }
            Err(e) => {
                log::warn!("Seed access denied: {e:?}");
                return None;
            }
        };
        // The 64-byte BIP-39 seed (empty passphrase; see FIRMWARE_PLAN.md for the
        // passphrase-account limitation).
        let master = ngwallet::bip39::MasterKey::from_entropy(
            &self.secp,
            Network::Bitcoin,
            entropy.bytes(),
            "",
            None,
        )
        .inspect_err(|e| log::error!("Master key derivation failed: {e:?}"))
        .ok()?;
        Some(master.key.0.to_vec())
    }

    #[cfg(not(feature = "gui-approval"))]
    fn approve_policy(&mut self, policy: &Policy) -> bool {
        log::info!("test-approval: auto-approving coinjoin policy {policy:?}");
        true
    }

    #[cfg(feature = "gui-approval")]
    fn approve_policy(&mut self, policy: &Policy) -> bool {
        use gui_server_api::navigation::alerts::{AlertResult, InvokeAlert};

        let line1 = format!(
            "Coordinator: {}\nAccount: #{} ({})",
            String::from_utf8_lossy(&policy.coordinator_id),
            policy.account,
            match policy.network {
                Network::Bitcoin => "mainnet",
                _ => "testnet",
            },
        );
        let line2 = format!(
            "Max fee: {} sats/round\nRounds: up to {}, valid {} min",
            policy.max_fee_contribution,
            policy.max_rounds,
            policy.valid_for_secs / 60,
        );
        let alert = InvokeAlert {
            app_title: Some("Wallet RPC".to_string()),
            title: "Authorize coinjoin?".to_string(),
            icon: "alert".to_string(),
            line1,
            line2: Some(line2),
            button1_title: "Authorize".to_string(),
            button2_title: Some("Deny".to_string()),
            button3_title: None,
        };

        match GuiApiLight::default().invoke_alert(alert) {
            Ok(AlertResult::Button1Pressed) => true,
            Ok(_) => false,
            Err(e) => {
                log::error!("Approval alert failed: {e:?}");
                false
            }
        }
    }
}

#[derive(server::Server)]
#[name = "os/wallet-rpc"]
pub struct WalletRpcServer {
    engine: Engine<KeyOsBackend>,
}

impl Server for WalletRpcServer {}

impl WalletRpcServer {
    pub fn new() -> Result<Self, WalletRpcError> {
        #[cfg(keyos)]
        {
            let mut usb_api = UsbDeviceEmulation::default();
            let interface_num = usb_api.registered_interfaces() as u16;
            usb_api.register_setup_responder(SetupResponder { interface_num })?;
            let [ep_out, ep_in] = usb_api.register_interface(
                USB_WALLET_IFCE_CLASS,
                USB_WALLET_IFCE_SUBCLASS,
                USB_WALLET_IFCE_PROTOCOL,
                &USB_WALLET_ENDPOINTS,
                &USB_WALLET_FUNC_DESCRIPTOR,
                0,
            )?;
            std::thread::spawn(|| usb_thread(ep_out, ep_in));
        }

        Ok(Self { engine: Engine::new(KeyOsBackend::new()) })
    }
}

impl ArchiveHandler<ProcessRpcFrame> for WalletRpcServer {
    fn handle(
        &mut self,
        ProcessRpcFrame(frame): ProcessRpcFrame,
        _sender: xous::PID,
        _context: &mut ServerContext<Self>,
    ) -> Vec<u8> {
        log::debug!("Processing RPC frame ({} bytes)", frame.len());
        self.engine.process_frame(&frame)
    }
}
