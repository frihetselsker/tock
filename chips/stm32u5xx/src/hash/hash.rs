// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright OxidOS Automotive 2026.

//! Interrupt-driven STM32U5 message digests.
//!
//! The four algorithm interfaces share one engine. Input is copied into the
//! hardware FIFO in bounded batches; no client buffer is retained or used for
//! DMA. Callbacks run only from interrupts or deferred calls. The active client
//! is snapshotted when an operation is accepted, so later client registration
//! cannot redirect an in-flight operation.

use core::cell::Cell;

use crate::hash::utils::FIFO_SIZE;

use super::utils::{Client, ClientCallback, Leftover, State};

use super::regs::{CR, HashRegisters, IMR, SR, STR};
use kernel::deferred_call::{DeferredCall, DeferredCallClient};
use kernel::hil::crypto::digest::{Digest, DigestClient, Md5, Sha1, Sha224, Sha256};
use kernel::utilities::StaticRef;
use kernel::utilities::cells::OptionalCell;
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable, Writeable};
use kernel::{ErrorCode, debug};

/// One HASH peripheral implementing MD5, SHA-1, SHA-224, and SHA-256.
pub struct Hash {
    regs: StaticRef<HashRegisters>,
    state: Cell<State>,
    remaining: Cell<usize>,
    leftover: Leftover,
    md5: OptionalCell<&'static dyn DigestClient<Md5>>,
    sha1: OptionalCell<&'static dyn DigestClient<Sha1>>,
    sha224: OptionalCell<&'static dyn DigestClient<Sha224>>,
    sha256: OptionalCell<&'static dyn DigestClient<Sha256>>,
    active: OptionalCell<Client>,
    cancel: Cell<bool>,
    deferred_call: DeferredCall,
}

impl Hash {
    /// Create an engine; register its deferred call before accepting requests.
    pub fn new(regs: StaticRef<HashRegisters>) -> Self {
        Self {
            regs,
            state: Cell::new(State::Idle {
                is_intermediate: false,
            }),
            remaining: Cell::new(0),
            leftover: Leftover::new(),
            md5: OptionalCell::empty(),
            sha1: OptionalCell::empty(),
            sha224: OptionalCell::empty(),
            sha256: OptionalCell::empty(),
            active: OptionalCell::empty(),
            cancel: Cell::new(false),
            deferred_call: DeferredCall::new(),
        }
    }

    pub(crate) fn handle_interrupt(&self) {
        self.regs.imr.set(0);
        match self.state.get() {
            State::Finishing { is_started: true } if self.regs.sr.is_set(SR::DCIS) => {
                if let Some(client) = self.active.get() {
                    if self.cancel.take() {
                        return self.finish(ClientCallback::OpDone, Err(ErrorCode::CANCEL));
                    }
                    let result = match client {
                        Client::Md5(client) => client.write_output(&self.output::<16>()),
                        Client::Sha1(client) => client.write_output(&self.output::<20>()),
                        Client::Sha224(client) => client.write_output(&self.output::<28>()),
                        Client::Sha256(client) => client.write_output(&self.output::<32>()),
                    };
                    self.finish(ClientCallback::OpDone, result);
                }
            }
            State::Finishing { is_started: false } if self.regs.sr.is_set(SR::DINIS) => {
                if self.cancel.take() {
                    return self.finish(ClientCallback::OpDone, Err(ErrorCode::CANCEL));
                }
                let leftover_bytes = self.leftover.len();
                let regs = self.regs;
                regs.din.set(self.leftover.to_le());
                regs.str.modify(STR::NBLW.val((leftover_bytes << 3) as u32));
                self.state.set(State::Finishing { is_started: true });
                regs.imr.modify(IMR::DCIE::SET);
                regs.str.modify(STR::DCAL::SET);
            }
            State::Feeding => {
                if let Some(client) = self.active.get() {
                    let result = (|| {
                        if self.cancel.take() {
                            return Err(ErrorCode::CANCEL);
                        }
                        let remaining = self.remaining.get();
                        let bytes_loaded = self.feed(remaining, client)?;
                        let remaining_updated =
                            remaining.checked_sub(bytes_loaded).ok_or(ErrorCode::FAIL)?;
                        self.remaining.set(remaining_updated);
                        Ok(())
                    })();
                    if result.is_err() || self.remaining.get() == 0 {
                        self.finish(ClientCallback::UpdateDone, result);
                    }
                }
            }
            _ => (),
        }
    }

    fn start(&self, client: Option<Client>) -> Result<(), ErrorCode> {
        if self.state.get()
            != (State::Idle {
                is_intermediate: false,
            })
        {
            return Err(ErrorCode::BUSY);
        }
        let client = client.ok_or(ErrorCode::RESERVE)?;
        let algorithm = match client {
            Client::Md5(_) => CR::ALGO::MD5,
            Client::Sha1(_) => CR::ALGO::SHA_1,
            Client::Sha224(_) => CR::ALGO::SHA2_224,
            Client::Sha256(_) => CR::ALGO::SHA2_256,
        };
        self.regs.cr.write(
            algorithm + CR::DATATYPE::_8bitData + CR::INIT::SET + CR::MDMAT::SET + CR::MODE::CLEAR,
        );
        self.regs.sr.modify(SR::DCIS::CLEAR + SR::DINIS::CLEAR);
        self.active.set(client);
        Ok(())
    }

    fn prepare_update(&self, len: usize) -> Result<(), ErrorCode> {
        if self.active.is_none() {
            return Err(ErrorCode::INVAL);
        }

        match self.state.get() {
            State::Idle { .. } => {}
            State::Feeding if self.remaining.get() != 0 => return Err(ErrorCode::BUSY),
            _ => return Err(ErrorCode::INVAL),
        }

        self.remaining.set(len);
        debug!("Set remaining in prepare_update: {}", len);
        self.state.set(State::Feeding);
        self.deferred_call.set();

        debug!("State::Feeding");

        Ok(())
    }

    fn feed(&self, remaining: usize, client: Client) -> Result<usize, ErrorCode> {
        let mut input = [0u8; FIFO_SIZE];
        let fifo_space =
            ((self.regs.sr.read(SR::NBWE) * 4) as usize).saturating_sub(self.leftover.len());
        debug!("Fifo space: {}", fifo_space);
        if fifo_space == 0 {
            self.regs.imr.write(IMR::DINIE::SET);
            return Ok(0);
        }
        let space_limit = fifo_space.min(FIFO_SIZE).min(remaining);
        let count = match client.read_input(&mut input[..space_limit]) {
            Ok(count) => count,
            Err(error) => {
                return Err(error);
            }
        };
        debug!("REad into input: {}", count);
        self.write_data_cpu(&input[..count])?;
        Ok(count)
    }

    fn write_data_cpu(&self, buffer: &[u8]) -> Result<(), ErrorCode> {
        let regs = self.regs;

        // Load leftover if it is not empty
        let buffer = if !self.leftover.is_empty() {
            let bytes_to_load = 4 - self.leftover.len();
            debug!("Need to add {} bytes to leftover", bytes_to_load);
            for i in 0..bytes_to_load {
                self.leftover.add(buffer[i])?;
            }
            regs.din.set(self.leftover.to_le());
            &buffer[bytes_to_load..]
        } else {
            buffer
        };

        let (words_to_load, leftover_to_load) = buffer.as_chunks::<4>();

        // Write 32-bit words
        for data in words_to_load {
            let d = u32::from_le_bytes(*data);
            debug!("Writing 0x{:02x}", d);
            regs.din.set(d);
        }

        // Accumulate leftover bytes
        for data in leftover_to_load {
            debug!("Accumulating 0x{:02x}", data);
            self.leftover.add(*data)?;
        }

        Ok(())
    }

    fn run(&self) -> Result<(), ErrorCode> {
        if self.active.is_none() {
            return Err(ErrorCode::INVAL);
        }

        debug!("Entered run");

        debug!("State: {:?}", self.state.get());

        match self.state.get() {
            State::Idle { is_intermediate } => {
                if !is_intermediate {
                    return Err(ErrorCode::INVAL);
                }
            }
            _ => return Err(ErrorCode::BUSY),
        }

        let regs = self.regs;
        let leftover_bytes = self.leftover.len();

        debug!("Before run: leftover len {}", leftover_bytes * 8);

        if !self.leftover.is_empty() {
            if !regs.sr.is_set(SR::BUSY) {
                let value = self.leftover.to_le();
                debug!("We are writing: 0x{:02x}", value);
                regs.din.set(value);
            } else {
                regs.imr.modify(IMR::DINIE::SET);
                self.state.set(State::Finishing { is_started: false });
                return Ok(());
            }
        }

        regs.str.modify(STR::NBLW.val((leftover_bytes * 8) as u32));
        regs.imr.modify(IMR::DCIE::SET);
        self.state.set(State::Finishing { is_started: true });
        regs.str.modify(STR::DCAL::SET);
        Ok(())
    }

    fn output<const LEN: usize>(&self) -> [u8; LEN] {
        let mut output = [0; LEN];
        for (bytes, register) in output
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(self.regs.hr.iter())
        {
            bytes.copy_from_slice(&register.get().to_be_bytes());
        }
        debug!("Output: {:02x?}", output);
        output
    }

    fn finish(&self, callback: ClientCallback, result: Result<(), ErrorCode>) {
        let reset_driver = || {
            self.regs.cr.modify(CR::INIT::SET);
            self.regs.sr.modify(SR::DCIS::CLEAR);
            self.leftover.reset();
            self.remaining.set(0);
            self.state.set(State::Idle {
                is_intermediate: false,
            });
        };

        match callback {
            ClientCallback::OpDone => {
                reset_driver();
                if let Some(client) = self.active.take() {
                    client.digest_done(result);
                }
            }
            ClientCallback::UpdateDone if result.is_err() => {
                reset_driver();
                if let Some(client) = self.active.take() {
                    client.update_done(result);
                }
            }
            ClientCallback::UpdateDone => {
                if let Some(client) = self.active.get() {
                    client.update_done(result);
                }
            }
        }
    }
}

impl DeferredCallClient for Hash {
    fn handle_deferred_call(&'static self) {
        if let Some(client) = self.active.get() {
            debug!("Entered deferred call");
            let result = (|| {
                if self.cancel.take() {
                    return Err(ErrorCode::CANCEL);
                }
                let remaining = self.remaining.get();
                debug!("Remaining: {} bytes", remaining);
                let bytes_loaded = self.feed(remaining, client)?;
                debug!("Bytes loaded: {}", bytes_loaded);
                let remaining_updated =
                    remaining.checked_sub(bytes_loaded).ok_or(ErrorCode::FAIL)?;
                self.remaining.set(remaining_updated);
                Ok(())
            })();
            if result.is_err() || self.remaining.get() == 0 {
                self.state.set(State::Idle {
                    is_intermediate: true,
                });
                self.finish(ClientCallback::UpdateDone, result);
            }
        }
    }

    fn register(&'static self) {
        self.deferred_call.register(self);
    }
}

impl Digest<Md5> for Hash {
    fn begin(&self) -> Result<(), ErrorCode> {
        self.start(self.md5.get().map(Client::Md5))
    }

    fn update(&self, len: usize) -> Result<(), ErrorCode> {
        self.prepare_update(len)
    }

    fn finalize(&self) -> Result<(), ErrorCode> {
        self.run()
    }

    fn cancel(&self) -> Result<(), ErrorCode> {
        if let State::Idle { .. } = self.state.get() {
            Err(ErrorCode::INVAL)
        } else {
            self.cancel.set(true);
            Ok(())
        }
    }

    fn set_client(&self, client: &'static dyn DigestClient<Md5>) {
        self.md5.set(client);
    }
}

impl Digest<Sha1> for Hash {
    fn begin(&self) -> Result<(), ErrorCode> {
        self.start(self.sha1.get().map(Client::Sha1))
    }

    fn update(&self, len: usize) -> Result<(), ErrorCode> {
        self.prepare_update(len)
    }

    fn finalize(&self) -> Result<(), ErrorCode> {
        self.run()
    }

    fn cancel(&self) -> Result<(), ErrorCode> {
        if let State::Idle { .. } = self.state.get() {
            Err(ErrorCode::INVAL)
        } else {
            self.cancel.set(true);
            Ok(())
        }
    }

    fn set_client(&self, client: &'static dyn DigestClient<Sha1>) {
        self.sha1.set(client);
    }
}

impl Digest<Sha224> for Hash {
    fn begin(&self) -> Result<(), ErrorCode> {
        self.start(self.sha224.get().map(Client::Sha224))
    }

    fn update(&self, len: usize) -> Result<(), ErrorCode> {
        self.prepare_update(len)
    }

    fn finalize(&self) -> Result<(), ErrorCode> {
        self.run()
    }

    fn cancel(&self) -> Result<(), ErrorCode> {
        if let State::Idle { .. } = self.state.get() {
            Err(ErrorCode::INVAL)
        } else {
            self.cancel.set(true);
            Ok(())
        }
    }

    fn set_client(&self, client: &'static dyn DigestClient<Sha224>) {
        self.sha224.set(client);
    }
}

impl Digest<Sha256> for Hash {
    fn begin(&self) -> Result<(), ErrorCode> {
        self.start(self.sha256.get().map(Client::Sha256))
    }

    fn update(&self, len: usize) -> Result<(), ErrorCode> {
        debug!("Reached prepare update");
        self.prepare_update(len)
    }

    fn finalize(&self) -> Result<(), ErrorCode> {
        self.run()
    }

    fn cancel(&self) -> Result<(), ErrorCode> {
        if let State::Idle { .. } = self.state.get() {
            Err(ErrorCode::INVAL)
        } else {
            self.cancel.set(true);
            Ok(())
        }
    }

    fn set_client(&self, client: &'static dyn DigestClient<Sha256>) {
        self.sha256.set(client);
    }
}
