// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright OxidOS Automotive 2026.

//! HASH core computing unit performing digest calculations for various modes.

use core::cell::Cell;
use core::cmp::min;

use crate::dma::{ChannelId, Dma};
use crate::hash::regs::HashRegisters;
use crate::hash::regs::{CR, IMR, SR, STR};
use crate::hash::utils::{DataType, HashClient, Leftover, State};

use cortexm33::dma_fence::CortexMDmaFence;
use kernel::ErrorCode;
use kernel::deferred_call::{DeferredCall, DeferredCallClient};
use kernel::hil::crypto::digest::{Client, Digest, Hmac, HmacClient, Mode, TransferMode};
use kernel::utilities::StaticRef;
use kernel::utilities::cells::{MapCell, OptionalCell};
use kernel::utilities::dma_slice::{DmaSubSlice, DmaSubSliceMut, DmaSubSliceMutImmut};
use kernel::utilities::leasable_buffer::SubSliceMutImmut;
use kernel::utilities::registers::FieldValue;
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable, Writeable};

const LONG_HMAC_KEY_LEN: usize = 64;
const FIFO_SIZE: usize = 16 * 4;

pub struct Hash<'a> {
    regs: StaticRef<HashRegisters>,
    dma: OptionalCell<&'a Dma>,
    dma_channel: Cell<Option<ChannelId>>,
    dma_buffer: MapCell<DmaSubSliceMutImmut<'static, u8>>,
    mode: Cell<Option<Mode>>,
    transfer_mode: Cell<TransferMode>,
    state: Cell<Option<State>>,
    leftover: Leftover,
    data_length: Cell<usize>,
    key_length: Cell<usize>,
    cancelled: Cell<bool>,
    client: OptionalCell<HashClient<'a>>,
    deferred_call: DeferredCall,
}

impl<'a> Hash<'a> {
    // Associates a DMA controller and channels with the HASH driver
    pub fn set_dma(hash: &'static Self, dma: &'a Dma, channel: ChannelId) {
        hash.dma.set(dma);
        hash.dma_channel.set(Some(channel));
        dma.set_client(channel, hash);
    }

    fn start_dma_transfer(
        &self,
        dma: &'a Dma,
        dma_channel: ChannelId,
        mut dma_buffer: SubSliceMutImmut<'static, u8>,
    ) -> Result<(), (ErrorCode, SubSliceMutImmut<'static, u8>)> {
        let leftover_loaded = if !self.leftover.is_empty() {
            // Imagine there is a situation when the FIFO is full,
            // and no more data can be written
            let (count, start) = self.trim_dma_subslice(&dma_buffer);
            dma_buffer.slice(count..);
            start
        } else {
            true
        };
        if leftover_loaded {
            // Truncate
            let count = self.truncate_dma_subslice(&dma_buffer);
            dma_buffer.slice(..dma_buffer.len() - count);
            if dma_buffer.len() == 0 {
                return Ok(());
            }

            // Trigger HASH
            let regs = self.regs;
            // Hardware fence
            // Load data only if we have a channel
            // Otherwise, it is meaningless
            let fence = unsafe { CortexMDmaFence::new() };
            // Convert subslice into DmaSlice
            let (dma_slice, ptr, len) = match dma_buffer {
                SubSliceMutImmut::Immutable(d) => {
                    let dma_slice = DmaSubSlice::new(d, fence);
                    // Extract the physical pointer and length for MMIO
                    let ptr = dma_slice.as_ptr() as u32;
                    let len = dma_slice.len() as u32;
                    (DmaSubSliceMutImmut::Immutable(dma_slice), ptr, len)
                }
                SubSliceMutImmut::Mutable(d) => {
                    let dma_slice = unsafe { DmaSubSliceMut::new(d, fence) };
                    // Extract the physical pointer and length for MMIO
                    let ptr = dma_slice.as_mut_ptr() as u32;
                    let len = dma_slice.len() as u32;
                    (DmaSubSliceMutImmut::Mutable(dma_slice), ptr, len)
                }
            };
            // Save DmaSlice in the peripheral struct
            self.dma_buffer.replace(dma_slice);
            dma.setup(dma_channel, crate::dma::DmaPeripheral::Hash, ptr, len);

            regs.imr.modify(IMR::DINIE::SET);
            regs.cr.modify(CR::DMAE::SET);

            Ok(())
        } else {
            Err((ErrorCode::FAIL, dma_buffer))
        }
    }
}

impl Hash<'_> {
    pub fn new(base: StaticRef<HashRegisters>) -> Self {
        Self {
            regs: base,
            dma: OptionalCell::empty(),
            dma_channel: Cell::new(None),
            dma_buffer: MapCell::empty(),
            mode: Cell::new(None),
            transfer_mode: Cell::new(TransferMode::DirectStream),
            state: Cell::new(None),
            data_length: Cell::new(0),
            key_length: Cell::new(0),
            cancelled: Cell::new(false),
            leftover: Leftover::new(),
            // fifo_length: MsgTracker::new(),
            client: OptionalCell::empty(),
            deferred_call: DeferredCall::new(),
        }
    }

    pub(crate) fn handle_interupts(&self) {
        // This function contains the state machine around the HASH core that orchestrates
        // the whole process around the digest calculation
        //
        // Simple digest calculation:
        // Add -> Callback -> (if FIFO is not empty) PreRun -> Run -> Callback
        //
        // HMAC digest calculation:
        // HmacInit -> HmacPreAuth -> Add -> Callback ->
        // (if FIFO is not empty) PreRun -> Run -> HmacPostAuth -> HmacFinalize -> Callback

        let regs = self.regs;
        // Disable all the interrupts
        regs.imr.modify(IMR::DCIE::CLEAR + IMR::DINIE::CLEAR);
        if let Some(client) = self.client.get() {
            if self.cancelled.take() {
                self.finish(Err(ErrorCode::CANCEL), client);
            } else {
                if let Some(state) = self.state.get() {
                    // Is final digest ready?
                    if regs.sr.is_set(SR::DCIS) {
                        match state {
                            State::Run(true, DataType::Input)
                            | State::Run(true, DataType::OuterKey) => {
                                self.finish(self.get_digest(), client);
                            }
                            _ => self.finish(Err(ErrorCode::FAIL), client),
                        }
                    }
                    // Is FIFO ready?
                    if regs.sr.is_set(SR::DINIS) {
                        match state {
                            State::Run(true, DataType::InnerKey) => {
                                state.update(Some(self.data_length.get()));
                            }
                            State::Run(true, DataType::Input) => {
                                state.update(Some(self.key_length.get()));
                            }
                            State::Run(false, data_type) => match self.run(data_type) {
                                Ok(false) => self.deferred_call.set(),
                                Ok(true) => self.state.set(state.update(None)),
                                Err(e) => self.finish(Err(e), client),
                            },
                            State::Add(left, data_type) => {
                                let bytes_loaded = self.load_data(client, data_type).unwrap_or(0);
                                let updated_length = left.checked_sub(bytes_loaded);
                                if updated_length.is_some() {
                                    self.state.set(state.update(updated_length));
                                    if !self.regs.sr.is_set(SR::BUSY) {
                                        self.deferred_call.set();
                                    }
                                } else {
                                    self.finish(Err(ErrorCode::FAIL), client);
                                }
                            }
                            _ => self.finish(Err(ErrorCode::FAIL), client),
                        }
                    }
                }
            }
        }
    }

    pub(crate) fn handle_dma_interrupt(&self) {
        let regs = self.regs;
        // Disable the DMA trigger to release the channel
        regs.cr.modify(CR::DMAE::CLEAR);
        if let Some(dma_slice) = self.dma_buffer.take() {
            if let (Some(state @ State::Add(len, _)), Some(client)) =
                (self.state.take(), self.client.get())
            {
                let mut subslice = match dma_slice {
                    DmaSubSliceMutImmut::Immutable(dma_sub_slice) => {
                        let subslice = dma_sub_slice.as_sub_slice();
                        SubSliceMutImmut::Immutable(subslice)
                    }
                    DmaSubSliceMutImmut::Mutable(dma_sub_slice_mut) => {
                        let fence = unsafe { CortexMDmaFence::new() };
                        let subslice = unsafe { dma_sub_slice_mut.take(fence) };
                        SubSliceMutImmut::Mutable(subslice)
                    }
                };
                if self.cancelled.take() {
                    self.clear_data();
                    subslice.reset();
                    client.dma_buffer_done(Err(ErrorCode::CANCEL), subslice);
                } else {
                    // ugly line of code
                    let updated_len = len.checked_sub(subslice.len());
                    if let Some(len) = updated_len {
                        subslice.slice(0..0);
                        self.state.set(state.update(updated_len));
                        if len == 0 {
                            self.deferred_call.set();
                        }
                        client.dma_buffer_done(Ok(()), subslice);
                    } else {
                        client.dma_buffer_done(Err(ErrorCode::FAIL), subslice);
                    }
                }
            }
        }
    }

    // Write digest back
    fn get_digest(&self) -> Result<(), ErrorCode> {
        let regs = self.regs;
        if let (Some(mode), Some(client)) = (self.mode.get(), self.client.get()) {
            for i in 0..mode.get_digest_len() {
                let d = regs.hr[i].get().to_be_bytes();
                let result = [d[0], d[1], d[2], d[3]];
                client.write_output(&result)?;
            }
            Ok(())
        } else {
            Err(ErrorCode::FAIL)
        }
    }

    fn load_data(&self, client: HashClient<'_>, data_type: DataType) -> Result<usize, ErrorCode> {
        let regs = self.regs;
        let mut buffer = [0u8; FIFO_SIZE];
        let bytes_read = match data_type {
            DataType::Input => client.read_input(&mut buffer)?,
            DataType::InnerKey | DataType::OuterKey => client.read_key(&mut buffer)?,
        };
        let bytes_written = {
            let mut offset = 0;
            // if leftover buffer is not empty, it should be written right now
            if !self.leftover.is_empty() {
                let bytes_to_load = min(self.leftover.bytes_left(), bytes_read);

                for data in buffer[offset..bytes_to_load].iter() {
                    self.leftover.add(*data);
                }

                if !regs.sr.is_set(SR::BUSY) {
                    regs.din.set(self.leftover.to_le());
                    offset += bytes_to_load
                } else {
                    return Ok(offset);
                }
            }

            let fifo_space = regs.sr.read(SR::NBWE) as usize;
            let bytes_to_load = min(bytes_read - offset, fifo_space);
            let (words_to_load, leftover_to_load) = (bytes_to_load / 4, bytes_to_load % 4);

            // Send the 32-bit wordss
            for data in buffer[offset..offset + (words_to_load * 4)].chunks_exact(4) {
                let d = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                regs.din.set(d);
            }

            offset += words_to_load * 4;

            if leftover_to_load != 0 {
                for data in buffer[offset..offset + leftover_to_load].iter() {
                    // Accumulate leftover bytes
                    self.leftover.add(*data);
                }
                offset += leftover_to_load;
            }

            Ok(offset)
        };

        bytes_written
    }

    /// Trim the subslice to get rid of the old leftover bytes.
    ///
    /// Fill the leftover buffer with bytes from the beginning of subslice.
    /// Return the tuple of number of bytes written and boolean values showing
    /// if the write operation was successful and there is no need to wait for the interrupt
    /// when the FIFO is free.
    fn trim_dma_subslice(&self, dma_buffer: &SubSliceMutImmut<'_, u8>) -> (usize, bool) {
        let bytes_to_write = min(self.leftover.bytes_left(), dma_buffer.len());
        for data_idx in 0..bytes_to_write {
            self.leftover.add(dma_buffer[data_idx]);
        }
        // Leftover buffer is full, it is time to empty it
        if self.leftover.is_full() {
            let regs = self.regs;
            if regs.sr.read(SR::NBWE) == 0 {
                // New data cannot be written at the moment
                // Wait for an interrupt when FIFO is empty
                return (bytes_to_write, false);
            } else {
                regs.din.set(self.leftover.to_le());
                // Leftover was written successfully
                return (bytes_to_write, true);
            }
        }
        (bytes_to_write, false)
    }

    /// Truncate the subslice to make its size divisible by 4.
    ///
    /// Fill the leftover buffer with bytes from the end of subslice.
    /// Return the number of bytes written.
    fn truncate_dma_subslice(&self, dma_buffer: &SubSliceMutImmut<'_, u8>) -> usize {
        let bytes_written = dma_buffer.len() % 4;
        for i in 0..bytes_written {
            let data_idx = (dma_buffer.len() - bytes_written) + i;
            self.leftover.add(dma_buffer[data_idx]);
        }
        bytes_written
    }

    /// Starts the final digest computation.
    ///
    /// Responsible only for starting the calculation
    fn run(&self, data_type: DataType) -> Result<bool, ErrorCode> {
        // No computations without the mode set
        if self.mode.get().is_none() {
            return Err(ErrorCode::INVAL);
        }
        let regs = self.regs;

        if !self.leftover.is_empty() {
            if !regs.sr.is_set(SR::BUSY) {
                regs.din.set(self.leftover.to_le());
            } else {
                return Ok(false);
            }
        }

        // Start the digest calculation
        let valid_mask = match data_type {
            DataType::Input => ((self.data_length.get() % 4) * 8) as u32,
            DataType::InnerKey | DataType::OuterKey => ((self.key_length.get() % 4) * 8) as u32,
        };
        regs.str.modify(STR::NBLW.val(valid_mask));
        regs.str.modify(STR::DCAL::SET);

        Ok(true)
    }

    fn parse_mode(&self, mode: Mode) -> Result<FieldValue<u32, CR::Register>, ErrorCode> {
        match mode {
            Mode::Md5 => Ok(CR::ALGO::MD5),
            Mode::Sha1 => Ok(CR::ALGO::SHA_1),
            Mode::Sha224 => Ok(CR::ALGO::SHA2_224),
            Mode::Sha256 => Ok(CR::ALGO::SHA2_256),
            Mode::Sha384 | Mode::Sha512_224 | Mode::Sha512_256 | Mode::Sha512 => {
                Err(ErrorCode::NOSUPPORT)
            }
        }
    }

    fn finish(&self, result: Result<(), ErrorCode>, client: HashClient<'_>) {
        self.state.take();
        self.clear_data();
        client.hash_done(result);
    }
}

impl crate::dma::DmaClient for Hash<'_> {
    fn transfer_done(&self, channel: ChannelId) {
        if let Some(ch) = self.dma_channel.get() {
            if ch == channel {
                self.handle_dma_interrupt();
            }
        }
    }
}

impl DeferredCallClient for Hash<'_> {
    fn handle_deferred_call(&self) {
        if let (Some(state), Some(client)) = (self.state.get(), self.client.get()) {
            if !self.cancelled.take() {
                let result = match state {
                    State::Add(left, data_type) => {
                        let bytes_loaded = self.load_data(client, data_type).unwrap_or(0);
                        let updated_length = left.checked_sub(bytes_loaded);
                        if updated_length.is_some() {
                            self.state.set(state.update(updated_length));
                            if !self.regs.sr.is_set(SR::BUSY) {
                                self.deferred_call.set();
                            }
                            Ok(())
                        } else {
                            Err(ErrorCode::FAIL)
                        }
                    }
                    State::Run(false, data_type) => {
                        // no need for setting deferred call, wait for an interrupt
                        self.run(data_type).map(|is_sent| {
                            if !is_sent {
                                self.deferred_call.set();
                            }
                        })
                    }
                    State::Run(true, _) => Err(ErrorCode::FAIL),
                };
                if result.is_err() {
                    self.finish(result, client);
                }
            } else {
                self.finish(Err(ErrorCode::CANCEL), client);
            }
        }
    }

    fn register(&'static self) {
        self.deferred_call.register(self);
    }
}

impl Digest for Hash<'_> {
    fn hash(&self, mode: Mode, len: usize) -> Result<TransferMode, ErrorCode> {
        if self.state.get().is_some() {
            return Err(ErrorCode::BUSY);
        }

        let mode_val = self.parse_mode(mode)?;
        self.data_length.set(len);
        self.state.set(Some(State::Add(len, DataType::Input)));
        self.mode.set(Some(mode));

        self.regs.cr.modify(
            mode_val + CR::MDMAT::SET + CR::DATATYPE::_8bitData + CR::MODE::CLEAR + CR::INIT::SET,
        );

        if self.dma.is_some() && self.dma_channel.get().is_some() && len >= 16 {
            self.transfer_mode.set(TransferMode::DMA);
            Ok(TransferMode::DMA)
        } else {
            self.transfer_mode.set(TransferMode::DirectStream);
            self.deferred_call.set();
            Ok(TransferMode::DirectStream)
        }
    }

    fn feed_dma_buffer(
        &self,
        dma_buffer: SubSliceMutImmut<'static, u8>,
    ) -> Result<(), (ErrorCode, SubSliceMutImmut<'static, u8>)> {
        if let (Some(dma), Some(dma_channel)) = (self.dma.get(), self.dma_channel.get()) {
            self.start_dma_transfer(dma, dma_channel, dma_buffer)?;
            Ok(())
        } else {
            Err((ErrorCode::INVAL, dma_buffer))
        }
    }

    fn clear_data(&self) {
        if self.state.get().is_none() {
            // No operation at the moment -> reset the peripheral keeping the settings
            self.regs.cr.modify(CR::INIT::SET);
            self.data_length.take();
            self.key_length.take();
        } else {
            // Set the cancellation flag and wait for the interrupt / deferred call
            self.cancelled.set(true);
        }
    }

    fn set_client(&self, client: &'static dyn kernel::hil::crypto::digest::Client) {
        self.client.set(HashClient::Hash(client));
    }
}

impl Hmac for Hash<'_> {
    fn authenticate(
        &self,
        mode: Mode,
        input_len: usize,
        key_len: usize,
    ) -> Result<TransferMode, ErrorCode> {
        if self.state.get().is_some() {
            return Err(ErrorCode::BUSY);
        }

        let mode_val = self.parse_mode(mode)?;

        let key_val = if key_len > LONG_HMAC_KEY_LEN {
            CR::LKEY::SET
        } else {
            CR::LKEY::CLEAR
        };
        self.key_length.set(key_len);
        self.data_length.set(input_len);
        self.regs.cr.modify(
            mode_val
                + key_val
                + CR::MDMAT::SET
                + CR::DATATYPE::_8bitData
                + CR::MODE::SET
                + CR::INIT::SET,
        );

        self.state
            .set(Some(State::Add(key_len, DataType::InnerKey)));
        self.mode.set(Some(mode));

        if self.dma.is_some() && self.dma_channel.get().is_some() && input_len >= 16 {
            self.transfer_mode.set(TransferMode::DMA);
            Ok(TransferMode::DMA)
        } else {
            self.transfer_mode.set(TransferMode::DirectStream);
            self.deferred_call.set();
            Ok(TransferMode::DirectStream)
        }
    }

    fn set_hmac_client(&self, client: &'static dyn HmacClient) {
        self.client.set(HashClient::Hmac(client));
    }
}
