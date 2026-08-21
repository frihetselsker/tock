// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright OxidOS Automotive 2026.

//! HASH core computing unit performing digest calculations for various modes.

use core::cell::Cell;
use core::cmp::min;

use crate::dma::{ChannelId, Dma};
use crate::hash::regs::HashRegisters;
use crate::hash::regs::{CR, IMR, SR, STR};
use crate::hash::utils::{DataType, HashClient, Leftover, State, TransferMode};

use cortexm33::dma_fence::CortexMDmaFence;
use kernel::deferred_call::{DeferredCall, DeferredCallClient};
use kernel::hil::crypto::digest::{Algorithm, Client, Digest, Hmac, HmacClient};
use kernel::utilities::StaticRef;
use kernel::utilities::cells::{MapCell, OptionalCell};
use kernel::utilities::dma_slice::DmaSubSliceMut;
use kernel::utilities::leasable_buffer::SubSliceMut;
use kernel::utilities::registers::FieldValue;
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable, Writeable};
use kernel::{ErrorCode, debug};

const LONG_HMAC_KEY_LEN: usize = 64;
const FIFO_SIZE: usize = 17 * 4;

pub struct Hash<'a> {
    regs: StaticRef<HashRegisters>,
    dma: OptionalCell<&'a Dma>,
    dma_channel: Cell<Option<ChannelId>>,
    dma_buffer: MapCell<DmaSubSliceMut<'static, u8>>,
    data_buffer: MapCell<SubSliceMut<'static, u8>>,
    algorithm: Cell<Option<Algorithm>>,
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
    pub fn set_dma(
        hash: &'static Self,
        dma: &'a Dma,
        channel: ChannelId,
        buffer: &'static mut [u8],
    ) {
        hash.dma.set(dma);
        hash.dma_channel.set(Some(channel));
        hash.data_buffer.put(SubSliceMut::new(buffer));
        dma.set_client(channel, hash);
    }

    fn start_dma_transfer(
        &self,
        dma: &'a Dma,
        dma_channel: ChannelId,
        dma_buffer: SubSliceMut<'static, u8>,
    ) {
        let fence = unsafe { CortexMDmaFence::new() };
        // Convert subslice into DmaSlice
        let dma_slice = unsafe { DmaSubSliceMut::new(dma_buffer, fence) };
        // Extract the physical pointer and length for MMIO
        let ptr = dma_slice.as_mut_ptr() as u32;
        let len = dma_slice.len() as u32;

        // debug!("DMA: current length of dma slice - {}", len);

        // Save DmaSlice in the peripheral struct
        self.dma_buffer.replace(dma_slice);
        dma.setup(dma_channel, crate::dma::DmaPeripheral::Hash, ptr, len);
        self.regs.cr.modify(CR::DMAE::SET);
    }
}

impl Hash<'_> {
    pub fn new(base: StaticRef<HashRegisters>) -> Self {
        Self {
            regs: base,
            dma: OptionalCell::empty(),
            dma_channel: Cell::new(None),
            dma_buffer: MapCell::empty(),
            data_buffer: MapCell::empty(),
            algorithm: Cell::new(None),
            transfer_mode: Cell::new(TransferMode::DirectStream),
            state: Cell::new(None),
            data_length: Cell::new(0),
            key_length: Cell::new(0),
            cancelled: Cell::new(false),
            leftover: Leftover::new(),
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
        debug!("INTERRUPT");
        // Disable all the interrupts
        regs.imr.modify(IMR::DCIE::CLEAR + IMR::DINIE::CLEAR);
        if let Some(client) = self.client.get() {
            if self.cancelled.take() {
                self.finish(Err(ErrorCode::CANCEL), client);
            } else {
                if let Some(state) = self.state.get() {
                    // Is final digest ready?
                    if regs.sr.is_set(SR::DCIS) {
                        debug!("Is final digest ready? - {:?}", state);
                        match state {
                            State::Run(true, DataType::Input)
                            | State::Run(true, DataType::OuterKey) => {
                                self.finish(self.get_digest(), client);
                            }
                            _ => self.finish(Err(ErrorCode::FAIL), client),
                        }
                    }
                    // Is FIFO ready?
                    else if regs.sr.is_set(SR::DINIS) {
                        debug!("Is FIFO ready? - {:?}", state);
                        match state {
                            State::Run(true, DataType::InnerKey) => {
                                self.state.set(state.update(Some(self.data_length.get())));
                                self.deferred_call.set();
                            }
                            State::Run(true, DataType::Input) => {
                                self.state.set(state.update(Some(self.key_length.get())));
                                self.deferred_call.set();
                            }
                            State::Run(false, data_type) => match self.run(data_type) {
                                Ok(true) => self.state.set(state.update(None)),
                                Ok(false) => self.finish(Err(ErrorCode::FAIL), client),
                                Err(e) => self.finish(Err(e), client),
                            },
                            State::Add(left, data_type) => {
                                let res = (|| {
                                    match self.transfer_mode.get() {
                                        TransferMode::DirectStream => {
                                            let (bytes_loaded, _) =
                                                self.load_data(client, data_type)?;
                                            let updated_length = left.checked_sub(bytes_loaded);
                                            self.state.set(state.update(updated_length));
                                            self.deferred_call.set();
                                            Ok(())
                                        }
                                        TransferMode::Dma(false) => {
                                            if self.leftover.is_full() {
                                                self.regs.din.set(self.leftover.to_le());
                                                let mut dma_buffer = self
                                                    .data_buffer
                                                    .take()
                                                    .ok_or(ErrorCode::FAIL)?;
                                                if let (Some(dma), Some(dma_channel)) =
                                                    (self.dma.get(), self.dma_channel.get())
                                                {
                                                    self.truncate_dma_subslice(&mut dma_buffer);
                                                    self.start_dma_transfer(
                                                        dma,
                                                        dma_channel,
                                                        dma_buffer,
                                                    );
                                                    self.transfer_mode.set(TransferMode::Dma(true));
                                                    Ok(())
                                                } else {
                                                    Err(ErrorCode::NODEVICE)
                                                }
                                            } else {
                                                // This should never happen
                                                Err(ErrorCode::FAIL)
                                            }
                                        }
                                        _ => {
                                            // This should never happen
                                            Err(ErrorCode::FAIL)
                                        }
                                    }
                                })();
                                if res.is_err() {
                                    self.finish(res, client);
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
        debug!("Dma interrupt received");
        regs.cr.modify(CR::DMAE::CLEAR);
        if let (Some(dma_slice), Some(client)) = (self.dma_buffer.take(), self.client.get()) {
            let fence = unsafe { CortexMDmaFence::new() };
            let mut subslice = unsafe { dma_slice.take(fence) };
            subslice.reset();
            self.transfer_mode.set(TransferMode::Dma(false));
            self.data_buffer.put(subslice);
            if self.cancelled.take() {
                self.finish(Err(ErrorCode::CANCEL), client);
            } else {
                self.deferred_call.set();
            }
        }
    }

    // Write digest back
    fn get_digest(&self) -> Result<(), ErrorCode> {
        let regs = self.regs;
        if let (Some(algo), Some(client)) = (self.algorithm.get(), self.client.get()) {
            for i in 0..(algo.get_digest_len() / 4) {
                let d = regs.hr[i].get().to_be_bytes();
                let result = [d[0], d[1], d[2], d[3]];
                debug!("Received: {:02x?}", result);
                client.write_output(&result)?;
            }
            Ok(())
        } else {
            Err(ErrorCode::FAIL)
        }
    }

    fn load_data(
        &self,
        client: HashClient<'_>,
        data_type: DataType,
    ) -> Result<(usize, bool), ErrorCode> {
        let read_from_client = |buf| match data_type {
            DataType::Input => client.read_input(buf),
            DataType::InnerKey | DataType::OuterKey => client.read_key(buf),
        };

        match (self.transfer_mode.get(), data_type) {
            (TransferMode::DirectStream, _) | (_, DataType::InnerKey | DataType::OuterKey) => {
                let mut buffer = [0u8; FIFO_SIZE];
                let fifo_space = (self.regs.sr.read(SR::NBWE) * 4) as usize;
                let space_limit = fifo_space.min(FIFO_SIZE);
                let bytes_read = read_from_client(&mut buffer[..space_limit])?;
                Ok((self.write_data_cpu(&buffer, bytes_read), true))
            }
            _ => {
                // debug!("Starting with DMA transfer");
                let mut dma_buffer = self.data_buffer.take().ok_or(ErrorCode::FAIL)?;
                dma_buffer.reset();
                let bytes_read = read_from_client(dma_buffer.as_mut_slice())?;
                dma_buffer.slice(..bytes_read);

                if let (Some(dma), Some(dma_channel)) = (self.dma.get(), self.dma_channel.get()) {
                    if !self.leftover.is_empty() {
                        debug!("Leftover is not empty, we need to fill it with bytes");
                        if self.trim_dma_subslice(&mut dma_buffer) {
                            if dma_buffer.len() == 0 {
                                debug!(
                                    "Already finished with everything, no need for DMA transfer"
                                );
                                return Ok((bytes_read, true));
                            }
                        } else {
                            self.data_buffer.put(dma_buffer);
                            return Ok((bytes_read, false));
                        }
                    }
                    if !dma_buffer.len().is_multiple_of(4) {
                        debug!("Dma buffer is not multiple of 4, truncate");
                        self.truncate_dma_subslice(&mut dma_buffer);
                        if dma_buffer.len() == 0 {
                            debug!("Already finished with everything, no need for DMA transfer");
                            return Ok((bytes_read, true));
                        }
                    }
                    self.start_dma_transfer(dma, dma_channel, dma_buffer);
                    debug!("Dma request sent");
                    Ok((bytes_read, true))
                } else {
                    Err(ErrorCode::NODEVICE)
                }
            }
        }
    }

    fn write_data_cpu(&self, buffer: &[u8], bytes_read: usize) -> usize {
        let regs = self.regs;
        let mut offset = 0;
        if !self.leftover.is_empty() {
            let bytes_to_accept = min(bytes_read, self.leftover.bytes_left());
            for data in buffer[..bytes_to_accept].iter() {
                debug!("Adding to thr leftover 0x{:02x}", *data);
                self.leftover.add(*data);
            }
            offset += bytes_to_accept;
            if !self.regs.sr.is_set(SR::BUSY) && self.leftover.is_full() {
                self.regs.din.set(self.leftover.to_le());
            } else {
                return bytes_to_accept;
            }
        }

        let (words_to_load, leftover_to_load) =
            ((bytes_read - offset) / 4, (bytes_read - offset) % 4);

        // Send the 32-bit wordss
        for data in buffer[offset..offset + (words_to_load * 4)].chunks_exact(4) {
            let d = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            debug!("W: 0x{:02x}", d);
            regs.din.set(d);
        }

        offset += words_to_load * 4;

        for data in buffer[offset..offset + leftover_to_load].iter() {
            debug!("R: 0x{:02x}", *data);
            // Accumulate leftover bytes
            self.leftover.add(*data);
        }

        bytes_read
    }

    /// Trim the subslice to get rid of the old leftover bytes.
    ///
    /// Fill the leftover buffer with bytes from the beginning of subslice.
    /// Return the tuple of number of bytes written and boolean values showing
    /// if the write operation was successful and there is no need to wait for the interrupt
    /// when the FIFO is free.
    fn trim_dma_subslice(&self, dma_buffer: &mut SubSliceMut<'_, u8>) -> bool {
        let bytes_to_write = min(self.leftover.bytes_left(), dma_buffer.len());
        debug!("Trim: bytes to write - {}", bytes_to_write);
        for data_idx in 0..bytes_to_write {
            self.leftover.add(dma_buffer[data_idx]);
        }
        dma_buffer.slice(bytes_to_write..);

        // Leftover buffer is full, it is time to empty it
        if self.leftover.is_full() {
            let regs = self.regs;
            if regs.sr.read(SR::NBWE) == 0 {
                // New data cannot be written at the moment
                // Wait for an interrupt when FIFO is empty
                debug!("Trim: busy, try at the interrupt");
                return false;
            } else {
                debug!("Writing the leftover to the register");
                regs.din.set(self.leftover.to_le());
                // Leftover was written successfully
                return true;
            }
        }
        true
    }

    /// Truncate the subslice to make its size divisible by 4.
    ///
    /// Fill the leftover buffer with bytes from the end of subslice.
    /// Return the number of bytes written.
    fn truncate_dma_subslice(&self, dma_buffer: &mut SubSliceMut<'_, u8>) {
        let bytes_written = dma_buffer.len() % 4;
        // debug!("Truncate: bytes written - {}", bytes_written);
        for i in 0..bytes_written {
            let data_idx = (dma_buffer.len() - bytes_written) + i;
            // debug!(
            //     "Truncate: Adding to the leftover - 0x{:02}",
            //     dma_buffer[data_idx]
            // );
            self.leftover.add(dma_buffer[data_idx]);
        }
        dma_buffer.slice(..dma_buffer.len() - bytes_written);
    }

    /// Starts the final digest computation.
    ///
    /// Responsible only for starting the calculation
    fn run(&self, data_type: DataType) -> Result<bool, ErrorCode> {
        // No computations without the algorithm set
        if self.algorithm.get().is_none() {
            return Err(ErrorCode::INVAL);
        }
        let regs = self.regs;

        if !self.leftover.is_empty() {
            if !regs.sr.is_set(SR::BUSY) {
                let leftover_content = self.leftover.to_le();
                debug!(
                    "There is leftover, we need to load it - 0x{:02x}",
                    leftover_content
                );
                regs.din.set(leftover_content);
            } else {
                return Ok(false);
            }
        }

        if let Some(state) = self.state.take() {
            self.state.set(state.update(None));
        } else {
            return Err(ErrorCode::FAIL);
        }

        // Start the digest calculation
        let data_length = match data_type {
            DataType::Input => {
                if self.key_length.get() > 0 {
                    regs.imr.modify(IMR::DINIE::SET);
                } else {
                    regs.imr.modify(IMR::DCIE::SET);
                }
                self.data_length.get() as u32
            }
            DataType::InnerKey => {
                regs.imr.modify(IMR::DINIE::SET);
                self.key_length.get() as u32
            }
            DataType::OuterKey => {
                regs.imr.modify(IMR::DCIE::SET);
                self.key_length.get() as u32
            }
        };
        debug!("Mask for starting: {}", (data_length % 4) * 8);
        regs.str.modify(STR::NBLW.val((data_length % 4) * 8));
        regs.str.modify(STR::DCAL::SET);

        Ok(true)
    }

    fn parse_algo(&self, algorithm: Algorithm) -> Result<FieldValue<u32, CR::Register>, ErrorCode> {
        match algorithm {
            Algorithm::Md5 => Ok(CR::ALGO::MD5),
            Algorithm::Sha1 => Ok(CR::ALGO::SHA_1),
            Algorithm::Sha224 => Ok(CR::ALGO::SHA2_224),
            Algorithm::Sha256 => Ok(CR::ALGO::SHA2_256),
            Algorithm::Sha384
            | Algorithm::Sha512_224
            | Algorithm::Sha512_256
            | Algorithm::Sha512 => Err(ErrorCode::NOSUPPORT),
        }
    }

    fn finish(&self, result: Result<(), ErrorCode>, client: HashClient<'_>) {
        self.state.take();
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
                debug!("DC - {:?}", state);
                let result = (|| {
                    match state {
                        State::Add(left, data_type) => {
                            let (bytes_loaded, is_dma_ready) = self.load_data(client, data_type)?;
                            let updated_length =
                                left.checked_sub(bytes_loaded).ok_or(ErrorCode::FAIL)?;
                            self.transfer_mode.set(TransferMode::Dma(is_dma_ready));
                            self.state.set(state.update(Some(updated_length)));
                            debug!("New: {:?}", self.state.get());
                            match (self.transfer_mode.get(), data_type) {
                                (TransferMode::DirectStream, _)
                                | (_, DataType::InnerKey | DataType::OuterKey) => {
                                    if !self.regs.sr.is_set(SR::BUSY) {
                                        self.deferred_call.set();
                                    } else {
                                        self.regs.imr.modify(IMR::DINIE::SET);
                                    }
                                }
                                (TransferMode::Dma(false), DataType::Input) => {
                                    self.regs.imr.modify(IMR::DINIE::SET);
                                }
                                (TransferMode::Dma(true), DataType::Input) => {
                                    debug!("DMA is loaded, waiting for the interrupt");
                                    // Do nothing, wait for an interrupt from DMA
                                }
                            }

                            Ok(())
                        }
                        State::Run(false, data_type) => {
                            // no need for setting deferred call, wait for an interrupt
                            self.run(data_type).map(|is_sent| {
                                if !is_sent {
                                    self.regs.imr.modify(IMR::DINIE::SET);
                                }
                            })
                        }
                        State::Run(true, _) => Err(ErrorCode::FAIL),
                    }
                })();
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
    fn hash(&self, algorithm: Algorithm, len: usize) -> Result<(), ErrorCode> {
        if self.state.get().is_some() {
            return Err(ErrorCode::BUSY);
        }

        let algo_val = self.parse_algo(algorithm)?;
        let regs = self.regs;
        self.data_length.set(len);
        self.state.set(Some(State::Add(len, DataType::Input)));
        self.algorithm.set(Some(algorithm));

        regs.cr.modify(
            algo_val + CR::MDMAT::SET + CR::DATATYPE::_8bitData + CR::MODE::CLEAR + CR::INIT::SET,
        );

        if self.dma.is_some() && self.dma_channel.get().is_some() {
            debug!("Hash: Setting DMA mode");
            self.transfer_mode.set(TransferMode::Dma(false));
        } else {
            debug!("Hash: Setting direct stream mode");
            self.transfer_mode.set(TransferMode::DirectStream);
        }
        self.deferred_call.set();
        Ok(())
    }

    fn clear_data(&self) {
        if self.state.get().is_none() {
            // No operation at the moment -> reset the peripheral keeping the settings
            self.regs.cr.modify(CR::INIT::SET);
            self.data_length.take();
            self.key_length.take();
            self.data_buffer.map(|buf| buf.reset());
            self.leftover.reset();
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
        algorithm: Algorithm,
        input_len: usize,
        key_len: usize,
    ) -> Result<(), ErrorCode> {
        if self.state.get().is_some() {
            return Err(ErrorCode::BUSY);
        }

        let algo_val = self.parse_algo(algorithm)?;

        let key_val = if key_len > LONG_HMAC_KEY_LEN {
            CR::LKEY::SET
        } else {
            CR::LKEY::CLEAR
        };
        self.key_length.set(key_len);
        self.data_length.set(input_len);
        self.regs.cr.modify(
            algo_val
                + key_val
                + CR::MDMAT::SET
                + CR::DATATYPE::_8bitData
                + CR::MODE::SET
                + CR::INIT::SET,
        );

        self.state
            .set(Some(State::Add(key_len, DataType::InnerKey)));
        self.algorithm.set(Some(algorithm));

        if self.dma.is_some() && self.dma_channel.get().is_some() && self.data_buffer.is_some() {
            self.transfer_mode.set(TransferMode::Dma(false));
        } else {
            self.transfer_mode.set(TransferMode::DirectStream);
        }
        self.deferred_call.set();
        Ok(())
    }

    fn set_hmac_client(&self, client: &'static dyn HmacClient) {
        self.client.set(HashClient::Hmac(client));
    }
}
