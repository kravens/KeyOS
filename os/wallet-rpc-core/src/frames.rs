// SPDX-FileCopyrightText: 2026 Kevin Ravensberg <kevinravensberg@proton.me>
// SPDX-License-Identifier: MIT OR GPL-3.0-or-later

//! Multi-report framing for the wallet RPC USB HID transport.
//!
//! HID reports are 64 bytes. Frames larger than one report are split:
//!
//! - Init report:         `[0x00][frame_len u16 LE][data ...61 bytes]`
//! - Continuation report: `[seq u8 (1..=0x7f)][data ...63 bytes]`
//!
//! A single host connection is assumed (no channels — unlike CTAPHID). A new
//! init report always resets reassembly, so a lost continuation can't wedge
//! the transport.

pub const REPORT_LEN: usize = 64;
const INIT_MARKER: u8 = 0x00;
const INIT_DATA_LEN: usize = REPORT_LEN - 3;
const CONT_DATA_LEN: usize = REPORT_LEN - 1;
/// Seq is 7 bits, so the largest frame is 3 + 61 + 127 * 63 bytes ≈ 8 KiB.
pub const MAX_FRAME_LEN: usize = INIT_DATA_LEN + 0x7f * CONT_DATA_LEN;

/// Split a frame into HID reports, each exactly `REPORT_LEN` bytes (zero padded).
pub fn split_frame(frame: &[u8]) -> Vec<[u8; REPORT_LEN]> {
    let mut reports = Vec::new();

    let mut report = [0u8; REPORT_LEN];
    report[0] = INIT_MARKER;
    report[1..3].copy_from_slice(&(frame.len() as u16).to_le_bytes());
    let first = frame.len().min(INIT_DATA_LEN);
    report[3..3 + first].copy_from_slice(&frame[..first]);
    reports.push(report);

    let mut offset = first;
    let mut seq = 1u8;
    while offset < frame.len() {
        let mut report = [0u8; REPORT_LEN];
        report[0] = seq;
        let chunk = (frame.len() - offset).min(CONT_DATA_LEN);
        report[1..1 + chunk].copy_from_slice(&frame[offset..offset + chunk]);
        reports.push(report);
        offset += chunk;
        seq += 1;
    }

    reports
}

/// Streaming reassembler for received reports.
#[derive(Default)]
pub struct Reassembler {
    expected_len: usize,
    next_seq: u8,
    buf: Vec<u8>,
}

impl Reassembler {
    /// Feed one report; returns the completed frame when the last chunk arrives.
    /// Malformed sequences reset state and return `None`.
    pub fn push_report(&mut self, report: &[u8]) -> Option<Vec<u8>> {
        if report.is_empty() {
            return None;
        }

        if report[0] == INIT_MARKER {
            if report.len() < 3 {
                self.reset();
                return None;
            }
            let len = u16::from_le_bytes([report[1], report[2]]) as usize;
            if len > MAX_FRAME_LEN {
                self.reset();
                return None;
            }
            self.expected_len = len;
            self.next_seq = 1;
            self.buf.clear();
            let data = &report[3..report.len().min(3 + len)];
            self.buf.extend_from_slice(data);
        } else {
            if self.expected_len == 0 || report[0] != self.next_seq {
                // Continuation without init, or out of order — drop everything.
                self.reset();
                return None;
            }
            self.next_seq += 1;
            let remaining = self.expected_len - self.buf.len();
            let data = &report[1..report.len().min(1 + remaining)];
            self.buf.extend_from_slice(data);
        }

        if self.buf.len() >= self.expected_len {
            let frame = core::mem::take(&mut self.buf);
            self.reset();
            Some(frame)
        } else {
            None
        }
    }

    fn reset(&mut self) {
        self.expected_len = 0;
        self.next_seq = 0;
        self.buf.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(len: usize) {
        let frame: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let reports = split_frame(&frame);
        let mut re = Reassembler::default();
        let mut out = None;
        for (i, report) in reports.iter().enumerate() {
            let res = re.push_report(report);
            if i + 1 < reports.len() {
                assert!(res.is_none(), "early completion at report {i}");
            } else {
                out = res;
            }
        }
        assert_eq!(out.expect("frame not completed"), frame);
    }

    #[test]
    fn single_report_frame() { roundtrip(10) }

    #[test]
    fn exact_init_capacity() { roundtrip(61) }

    #[test]
    fn two_reports() { roundtrip(62) }

    #[test]
    fn psbt_sized_frame() { roundtrip(4000) }

    #[test]
    fn max_frame() { roundtrip(MAX_FRAME_LEN) }

    #[test]
    fn empty_frame() {
        let reports = split_frame(&[]);
        assert_eq!(reports.len(), 1);
        let mut re = Reassembler::default();
        assert_eq!(re.push_report(&reports[0]), Some(vec![]));
    }

    #[test]
    fn out_of_order_cont_resets() {
        let frame: Vec<u8> = vec![7; 200];
        let reports = split_frame(&frame);
        let mut re = Reassembler::default();
        assert!(re.push_report(&reports[0]).is_none());
        assert!(re.push_report(&reports[2]).is_none()); // skipped seq 1
        // subsequent valid transfer still works
        roundtrip(200);
    }

    #[test]
    fn cont_without_init_ignored() {
        let mut re = Reassembler::default();
        let mut report = [0u8; REPORT_LEN];
        report[0] = 1;
        assert!(re.push_report(&report).is_none());
    }

    #[test]
    fn init_resets_partial_frame() {
        let frame: Vec<u8> = vec![9; 200];
        let reports = split_frame(&frame);
        let mut re = Reassembler::default();
        assert!(re.push_report(&reports[0]).is_none());
        // new init mid-transfer wins
        let small = split_frame(&[1, 2, 3]);
        assert_eq!(re.push_report(&small[0]), Some(vec![1, 2, 3]));
    }
}
