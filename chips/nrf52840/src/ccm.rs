// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! AES-128 Counter with CBC-MAC (CCM) peripheral.
//!
//! The nRF52840 CCM peripheral implements the Bluetooth Low Energy packet
//! profile rather than arbitrary NIST CCM. It supports a 13-byte nonce, one
//! byte of associated data subject to the BLE header mask, a 4-byte tag, and
//! payloads of at most 251 bytes.

use core::cell::Cell;

use kernel::ErrorCode;
use kernel::deferred_call::{DeferredCall, DeferredCallClient};
use kernel::hil::crypto::cipher::{self, Aes128, CcmTagLength, Operation};
use kernel::utilities::cells::{MapCell, OptionalCell};
use nrf5x_unsafe::ccm::{
    CCM_CONFIG_SIZE, CCM_CONFIG_START, CCM_INPUT_START, CCM_MAX_PAYLOAD_SIZE, CCM_OUTPUT_START,
    CCM_PACKET_HEADER_SIZE, CCM_TAG_SIZE, CcmDmaResult,
};
pub use nrf5x_unsafe::ccm::{CcmData, CcmRegisters, CcmRegistersManager};

const KEY_SIZE: usize = 16;
const NONCE_SIZE: usize = 13;
const ASSOCIATED_DATA_SIZE: usize = 1;
const BLE_HEADER_MASK: u8 = 0xe3;
const IO_CHUNK_SIZE: usize = 32;

/// nRF52840 AES-128 CCM peripheral.
pub struct Ccm {
    registers: CcmRegistersManager,
    data: MapCell<&'static mut [u8]>,
    client: OptionalCell<&'static dyn cipher::CcmClient<Aes128>>,
    active: Cell<bool>,
    len: Cell<usize>,
    operation: Cell<Operation>,
    deferred_call: DeferredCall,
}

impl Ccm {
    pub fn new(registers: CcmRegistersManager, data: &'static mut CcmData) -> Self {
        Self {
            registers,
            data: MapCell::new(data.as_mut_slice()),
            client: OptionalCell::empty(),
            active: Cell::new(false),
            len: Cell::new(0),
            operation: Cell::new(Operation::Encrypt),
            deferred_call: DeferredCall::new(),
        }
    }

    fn prepare_and_start(&self) {
        if !self.active.get() {
            return;
        }

        let result = self.client.map_or(Err(ErrorCode::OFF), |client| {
            self.data.map_or(Err(ErrorCode::FAIL), |data| {
                client.read_key(&mut data[CCM_CONFIG_START..CCM_CONFIG_START + KEY_SIZE])?;

                let mut nonce = [0; NONCE_SIZE];
                let nonce_len = client.read_nonce(&mut nonce)?;
                if !(7..=NONCE_SIZE).contains(&nonce_len) {
                    return Err(ErrorCode::INVAL);
                }
                if nonce_len != NONCE_SIZE {
                    return Err(ErrorCode::NOSUPPORT);
                }

                for (index, byte) in nonce[..5].iter().enumerate() {
                    data[CCM_CONFIG_START + KEY_SIZE + index] = *byte;
                }
                data[CCM_CONFIG_START + KEY_SIZE + 4] = nonce[4] & 0x7f;
                data[CCM_CONFIG_START + KEY_SIZE + 5..CCM_CONFIG_START + KEY_SIZE + 8].fill(0);
                data[CCM_CONFIG_START + KEY_SIZE + 8] = nonce[4] >> 7;
                data[CCM_CONFIG_START + KEY_SIZE + 9..CCM_CONFIG_START + CCM_CONFIG_SIZE]
                    .copy_from_slice(&nonce[5..]);

                let mut associated_data = [0; ASSOCIATED_DATA_SIZE];
                let associated_data_len = client.read_associated_data(&mut associated_data)?;
                if associated_data_len != ASSOCIATED_DATA_SIZE {
                    return Err(ErrorCode::INVAL);
                }
                if associated_data[0] & !BLE_HEADER_MASK != 0 {
                    return Err(ErrorCode::NOSUPPORT);
                }

                data[CCM_INPUT_START] = associated_data[0];
                data[CCM_INPUT_START + 1] = (self.len.get()
                    + if self.operation.get() == Operation::Decrypt {
                        CCM_TAG_SIZE
                    } else {
                        0
                    }) as u8;
                data[CCM_INPUT_START + 2] = 0;

                let input_len = self.len.get()
                    + if self.operation.get() == Operation::Decrypt {
                        CCM_TAG_SIZE
                    } else {
                        0
                    };
                let mut input_offset = 0;
                while input_offset < input_len {
                    let requested = core::cmp::min(IO_CHUNK_SIZE, input_len - input_offset);
                    let start = CCM_INPUT_START + CCM_PACKET_HEADER_SIZE + input_offset;
                    let bytes_read = client.read_input(&mut data[start..start + requested])?;
                    if bytes_read == 0 || bytes_read > requested {
                        return Err(ErrorCode::INVAL);
                    }
                    input_offset += bytes_read;
                }

                Ok(())
            })
        });

        if let Err(error) = result {
            self.abort(error);
            return;
        }

        match self.data.take() {
            Some(data) => {
                if let Err(data) = self
                    .registers
                    .start_ccm_dma(data, self.operation.get() == Operation::Decrypt)
                {
                    self.data.replace(data);
                    self.abort(ErrorCode::BUSY);
                }
            }
            None => self.abort(ErrorCode::FAIL),
        }
    }

    fn finish(&self, result: Result<(), ErrorCode>) {
        self.active.set(false);
        self.client.map(|client| client.crypt_done(result));
    }

    fn abort(&self, error: ErrorCode) {
        self.finish(Err(error));
    }

    pub fn handle_interrupt(&self) {
        let mic_valid = match self.registers.handle_interrupt() {
            Some(CcmDmaResult::Complete { buffer, mic_valid }) => {
                self.data.replace(buffer);
                mic_valid
            }
            Some(CcmDmaResult::Error(buffer)) => {
                self.data.replace(buffer);
                self.finish(Err(ErrorCode::FAIL));
                return;
            }
            None => return,
        };

        if self.operation.get() == Operation::Decrypt && !mic_valid {
            self.finish(Err(ErrorCode::FAIL));
            return;
        }

        let output_offset = if self.operation.get() == Operation::Encrypt {
            CCM_PACKET_HEADER_SIZE
        } else {
            0
        };
        let output_len = self.len.get()
            + if self.operation.get() == Operation::Encrypt {
                CCM_TAG_SIZE
            } else {
                0
            };
        let result = self.client.map_or(Err(ErrorCode::OFF), |client| {
            self.data.map_or(Err(ErrorCode::FAIL), |data| {
                let mut output_offset_in_message = 0;
                while output_offset_in_message < output_len {
                    let chunk_len =
                        core::cmp::min(IO_CHUNK_SIZE, output_len - output_offset_in_message);
                    let start = CCM_OUTPUT_START + output_offset + output_offset_in_message;
                    client.write_output(&data[start..start + chunk_len])?;
                    output_offset_in_message += chunk_len;
                }
                Ok(())
            })
        });

        match result {
            Ok(()) => self.finish(Ok(())),
            Err(error) => self.abort(error),
        }
    }
}

impl cipher::Ccm<Aes128> for Ccm {
    fn crypt(
        &self,
        len: usize,
        associated_data_len: usize,
        tag_len: CcmTagLength,
        operation: Operation,
    ) -> Result<(), ErrorCode> {
        if self.active.get() {
            return Err(ErrorCode::BUSY);
        }
        if tag_len != CcmTagLength::Tag32 || associated_data_len != ASSOCIATED_DATA_SIZE {
            return Err(ErrorCode::NOSUPPORT);
        }
        if len > CCM_MAX_PAYLOAD_SIZE {
            return Err(ErrorCode::SIZE);
        }
        if self.client.is_none() {
            return Err(ErrorCode::OFF);
        }

        self.len.set(len);
        self.operation.set(operation);
        self.active.set(true);
        self.deferred_call.set();
        Ok(())
    }

    fn set_client(&self, client: &'static dyn cipher::CcmClient<Aes128>) {
        self.client.set(client);
    }
}

impl DeferredCallClient for Ccm {
    fn handle_deferred_call(&self) {
        self.prepare_and_start();
    }

    fn register(&'static self) {
        self.deferred_call.register(self);
    }
}
