// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! AES-128 Electronic Codebook (ECB) peripheral.

use core::cell::Cell;

use kernel::ErrorCode;
use kernel::deferred_call::{DeferredCall, DeferredCallClient};
use kernel::hil::crypto::cipher::{self, Aes128, Operation};
use kernel::utilities::cells::{MapCell, OptionalCell};
use kernel::utilities::registers::interfaces::{Readable, Writeable};
pub use nrf5x_unsafe::aes::{AesEcbRegisters, AesEcbRegistersManager};
use nrf5x_unsafe::aes::{Event, Intenclr, Intenset};

const KEY_START: usize = 0;
const INPUT_START: usize = 16;
const OUTPUT_START: usize = 32;
const BLOCK_SIZE: usize = 16;

/// nRF5x AES-128 ECB peripheral.
///
/// The hardware supports encryption only. Decryption requests return
/// [`ErrorCode::NOSUPPORT`].
pub struct Ecb {
    registers: AesEcbRegistersManager,
    data: MapCell<&'static mut [u8]>,
    client: OptionalCell<&'static dyn cipher::EcbClient<Aes128>>,
    active: Cell<bool>,
    len: Cell<usize>,
    offset: Cell<usize>,
    deferred_call: DeferredCall,
}

impl Ecb {
    pub fn new(registers: AesEcbRegistersManager, data: &'static mut [u8; 48]) -> Self {
        Self {
            registers,
            data: MapCell::new(data),
            client: OptionalCell::empty(),
            active: Cell::new(false),
            len: Cell::new(0),
            offset: Cell::new(0),
            deferred_call: DeferredCall::new(),
        }
    }

    fn start_next_block(&self) {
        if !self.active.get() {
            return;
        }

        if self.offset.get() == self.len.get() {
            self.finish(Ok(()));
            return;
        }

        let result = self.client.map_or(Err(ErrorCode::OFF), |client| {
            self.data.map_or(Err(ErrorCode::FAIL), |data| {
                if self.offset.get() == 0 {
                    client.read_key(&mut data[KEY_START..INPUT_START])?;
                }

                let mut bytes_read = 0;
                while bytes_read < BLOCK_SIZE {
                    let input = &mut data[INPUT_START + bytes_read..OUTPUT_START];
                    let read = client.read_input(input)?;
                    if read == 0 || read > input.len() {
                        return Err(ErrorCode::INVAL);
                    }
                    bytes_read += read;
                }

                Ok(())
            })
        });

        if let Err(error) = result {
            self.abort(error);
            return;
        }

        self.registers
            .registers
            .event_errorecb
            .write(Event::READY::CLEAR);
        self.registers
            .registers
            .intenset
            .write(Intenset::ENDECB::SET + Intenset::ERRORECB::SET);

        match self.data.take() {
            Some(data) => {
                if let Err(data) = self.registers.start_ecb_dma(data) {
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
        self.registers
            .registers
            .intenclr
            .write(Intenclr::ENDECB::SET + Intenclr::ERRORECB::SET);
        self.finish(Err(error));
    }

    pub fn handle_interrupt(&self) {
        self.registers
            .registers
            .intenclr
            .write(Intenclr::ENDECB::SET + Intenclr::ERRORECB::SET);

        if self.registers.registers.event_errorecb.is_set(Event::READY) {
            self.registers
                .finish_ecb_dma()
                .map(|data| self.data.replace(data));
            self.abort(ErrorCode::FAIL);
        } else if self.registers.registers.event_endecb.is_set(Event::READY) {
            self.registers
                .finish_ecb_dma()
                .map(|data| self.data.replace(data));

            let mut output = [0; BLOCK_SIZE];
            let result = self.data.map_or(Err(ErrorCode::FAIL), |data| {
                output.copy_from_slice(&data[OUTPUT_START..]);
                Ok(())
            });
            if let Err(error) = result {
                self.abort(error);
                return;
            }

            let result = self
                .client
                .map_or(Err(ErrorCode::OFF), |client| client.write_output(&output));
            if let Err(error) = result {
                self.abort(error);
                return;
            }

            self.offset.set(self.offset.get() + BLOCK_SIZE);
            self.deferred_call.set();
        }
    }
}

impl cipher::Ecb<Aes128> for Ecb {
    fn crypt(&self, len: usize, operation: Operation) -> Result<(), ErrorCode> {
        if self.active.get() {
            return Err(ErrorCode::BUSY);
        }
        if operation == Operation::Decrypt {
            return Err(ErrorCode::NOSUPPORT);
        }
        if !len.is_multiple_of(BLOCK_SIZE) {
            return Err(ErrorCode::INVAL);
        }
        if self.client.is_none() {
            return Err(ErrorCode::OFF);
        }

        self.len.set(len);
        self.offset.set(0);
        self.active.set(true);
        self.deferred_call.set();
        Ok(())
    }

    fn set_client(&self, client: &'static dyn cipher::EcbClient<Aes128>) {
        self.client.set(client);
    }
}

impl DeferredCallClient for Ecb {
    fn handle_deferred_call(&self) {
        self.start_next_block();
    }

    fn register(&'static self) {
        self.deferred_call.register(self);
    }
}
