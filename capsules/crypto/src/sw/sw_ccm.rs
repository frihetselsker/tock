// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! Software implementation of AES-128 CCM over an ECB implementation.

use capsules_core::driver_mutex::{
    DriverMutex, DriverMutexAny, DriverMutexClient, DriverMutexHandle, DriverMutexRef,
};
use core::cell::Cell;
use kernel::ErrorCode;
use kernel::hil::crypto::cipher::{self, Aes128, CcmTagLength, Ecb, Operation};
use kernel::utilities::cells::{MapCell, OptionalCell};

const BLOCK_SIZE: usize = 16;
const KEY_SIZE: usize = 16;
const MAX_NONCE_SIZE: usize = 13;
const MAX_AAD_PREFIX_SIZE: usize = 10;

#[derive(Clone, Copy, PartialEq)]
enum State {
    Idle,
    WaitingForEcb,
    Mac,
    Tag,
    Payload,
}

#[derive(Clone, Copy, PartialEq)]
enum MacStage {
    B0,
    AssociatedData,
    Payload,
}

/// AES-128 CCM implemented in software using an encryption-only ECB driver.
///
/// The `workspace` passed to [`SoftwareCcm::new`] must be large enough to hold
/// the payload and authentication tag. Encryption retains the plaintext there
/// while computing the CBC-MAC, and decryption retains plaintext there until
/// authentication succeeds.
///
/// A `SoftwareCcm` must be registered with its ECB mutex using
/// [`SoftwareCcm::register`] after it has been placed in static memory.
pub struct SoftwareCcm<E: Ecb<Aes128> + 'static> {
    ecb_mutex: &'static DriverMutex<E>,
    ecb_handle: OptionalCell<DriverMutexHandle>,
    ecb: MapCell<DriverMutexRef<E>>,
    client: OptionalCell<&'static dyn cipher::CcmClient<Aes128>>,
    workspace: MapCell<&'static mut [u8]>,

    state: Cell<State>,
    operation: Cell<Operation>,
    len: Cell<usize>,
    associated_data_len: Cell<usize>,
    tag_len: Cell<usize>,

    key: Cell<[u8; KEY_SIZE]>,
    nonce: Cell<[u8; MAX_NONCE_SIZE]>,
    nonce_len: Cell<usize>,

    mac_stage: Cell<MacStage>,
    mac: Cell<[u8; BLOCK_SIZE]>,
    aad_prefix: Cell<[u8; MAX_AAD_PREFIX_SIZE]>,
    aad_prefix_len: Cell<usize>,
    aad_encoded_offset: Cell<usize>,
    aad_padded_len: Cell<usize>,
    payload_offset: Cell<usize>,
    tag: Cell<[u8; BLOCK_SIZE]>,

    ecb_input: Cell<[u8; BLOCK_SIZE]>,
    ecb_input_offset: Cell<usize>,
    ecb_output: Cell<[u8; BLOCK_SIZE]>,
    ecb_output_offset: Cell<usize>,
}

impl<E: Ecb<Aes128> + 'static> SoftwareCcm<E> {
    /// Create a software CCM implementation over a mutex-protected ECB driver.
    pub fn new(ecb_mutex: &'static DriverMutex<E>, workspace: &'static mut [u8]) -> Self {
        Self {
            ecb_mutex,
            ecb_handle: OptionalCell::empty(),
            ecb: MapCell::empty(),
            client: OptionalCell::empty(),
            workspace: MapCell::new(workspace),
            state: Cell::new(State::Idle),
            operation: Cell::new(Operation::Encrypt),
            len: Cell::new(0),
            associated_data_len: Cell::new(0),
            tag_len: Cell::new(0),
            key: Cell::new([0; KEY_SIZE]),
            nonce: Cell::new([0; MAX_NONCE_SIZE]),
            nonce_len: Cell::new(0),
            mac_stage: Cell::new(MacStage::B0),
            mac: Cell::new([0; BLOCK_SIZE]),
            aad_prefix: Cell::new([0; MAX_AAD_PREFIX_SIZE]),
            aad_prefix_len: Cell::new(0),
            aad_encoded_offset: Cell::new(0),
            aad_padded_len: Cell::new(0),
            payload_offset: Cell::new(0),
            tag: Cell::new([0; BLOCK_SIZE]),
            ecb_input: Cell::new([0; BLOCK_SIZE]),
            ecb_input_offset: Cell::new(0),
            ecb_output: Cell::new([0; BLOCK_SIZE]),
            ecb_output_offset: Cell::new(0),
        }
    }

    /// Register this CCM implementation as a client of its ECB mutex.
    pub fn register(&'static self) -> Result<(), ErrorCode> {
        if self.ecb_handle.is_some() {
            return Err(ErrorCode::ALREADY);
        }

        let handle = self.ecb_mutex.add_client(self).ok_or(ErrorCode::NOMEM)?;
        self.ecb_handle.set(handle);
        Ok(())
    }

    fn aad_prefix(associated_data_len: usize) -> ([u8; MAX_AAD_PREFIX_SIZE], usize) {
        let mut prefix = [0; MAX_AAD_PREFIX_SIZE];

        if associated_data_len == 0 {
            (prefix, 0)
        } else if associated_data_len < 0xff00 {
            prefix[..2].copy_from_slice(&(associated_data_len as u16).to_be_bytes());
            (prefix, 2)
        } else if u32::try_from(associated_data_len).is_ok() {
            prefix[..2].copy_from_slice(&0xfffe_u16.to_be_bytes());
            prefix[2..6].copy_from_slice(&(associated_data_len as u32).to_be_bytes());
            (prefix, 6)
        } else {
            prefix[..2].copy_from_slice(&0xffff_u16.to_be_bytes());
            prefix[2..].copy_from_slice(&(associated_data_len as u64).to_be_bytes());
            (prefix, 10)
        }
    }

    fn payload_fits_nonce(payload_len: usize, nonce_len: usize) -> bool {
        let length_bytes = BLOCK_SIZE - 1 - nonce_len;
        if length_bytes >= core::mem::size_of::<usize>() {
            true
        } else {
            payload_len < (1_usize << (length_bytes * 8))
        }
    }

    fn encode_length(block: &mut [u8; BLOCK_SIZE], value: usize, bytes: usize) {
        let mut remaining = value;
        for byte in block[BLOCK_SIZE - bytes..].iter_mut().rev() {
            *byte = remaining as u8;
            remaining >>= 8;
        }
    }

    fn read_full_input(&self, input_len: usize) -> Result<(), ErrorCode> {
        self.client.map_or(Err(ErrorCode::OFF), |client| {
            self.workspace.map_or(Err(ErrorCode::NOMEM), |workspace| {
                let mut offset = 0;
                while offset < input_len {
                    let destination = &mut workspace[offset..input_len];
                    let read = client.read_input(destination)?;
                    if read == 0 || read > destination.len() {
                        return Err(ErrorCode::INVAL);
                    }
                    offset += read;
                }
                Ok(())
            })
        })
    }

    fn read_associated_data(&self, destination: &mut [u8]) -> Result<(), ErrorCode> {
        self.client.map_or(Err(ErrorCode::OFF), |client| {
            let mut offset = 0;
            while offset < destination.len() {
                let remaining = &mut destination[offset..];
                let read = client.read_associated_data(remaining)?;
                if read == 0 || read > remaining.len() {
                    return Err(ErrorCode::INVAL);
                }
                offset += read;
            }
            Ok(())
        })
    }

    fn initialize(&self) -> Result<(), ErrorCode> {
        let mut key = [0; KEY_SIZE];
        let mut nonce = [0; MAX_NONCE_SIZE];
        let nonce_len = self.client.map_or(Err(ErrorCode::OFF), |client| {
            client.read_key(&mut key)?;
            client.read_nonce(&mut nonce)
        })?;

        if !(7..=MAX_NONCE_SIZE).contains(&nonce_len) {
            return Err(ErrorCode::INVAL);
        }
        if !Self::payload_fits_nonce(self.len.get(), nonce_len) {
            return Err(ErrorCode::SIZE);
        }

        self.key.set(key);
        self.nonce.set(nonce);
        self.nonce_len.set(nonce_len);

        let input_len = match self.operation.get() {
            Operation::Encrypt => self.len.get(),
            Operation::Decrypt => self
                .len
                .get()
                .checked_add(self.tag_len.get())
                .ok_or(ErrorCode::SIZE)?,
        };
        self.read_full_input(input_len)
    }

    fn start_ecb_block(&self, state: State, input: [u8; BLOCK_SIZE]) {
        self.state.set(state);
        self.ecb_input.set(input);
        self.ecb_input_offset.set(0);
        self.ecb_output.set([0; BLOCK_SIZE]);
        self.ecb_output_offset.set(0);

        let result = self.ecb.map_or(Err(ErrorCode::FAIL), |ecb| {
            ecb.crypt(BLOCK_SIZE, Operation::Encrypt)
        });
        if let Err(error) = result {
            self.finish(Err(error));
        }
    }

    fn xor_mac(&self, block: &mut [u8; BLOCK_SIZE]) {
        for (byte, mac_byte) in block.iter_mut().zip(self.mac.get().iter()) {
            *byte ^= *mac_byte;
        }
    }

    fn start_mac(&self) {
        self.mac.set([0; BLOCK_SIZE]);
        self.mac_stage.set(MacStage::B0);
        self.aad_encoded_offset.set(0);
        self.payload_offset.set(0);

        let nonce_len = self.nonce_len.get();
        let length_bytes = BLOCK_SIZE - 1 - nonce_len;
        let mut block = [0; BLOCK_SIZE];
        block[0] = if self.associated_data_len.get() > 0 {
            1 << 6
        } else {
            0
        };
        block[0] |= (((self.tag_len.get() - 2) / 2) as u8) << 3;
        block[0] |= (length_bytes - 1) as u8;
        block[1..1 + nonce_len].copy_from_slice(&self.nonce.get()[..nonce_len]);
        Self::encode_length(&mut block, self.len.get(), length_bytes);

        self.start_ecb_block(State::Mac, block);
    }

    fn start_aad_block(&self) {
        let block_start = self.aad_encoded_offset.get();
        let block_end = block_start + BLOCK_SIZE;
        let prefix_len = self.aad_prefix_len.get();
        let data_end = prefix_len + self.associated_data_len.get();
        let mut block = [0; BLOCK_SIZE];

        if block_start < prefix_len {
            let prefix_end = prefix_len.min(block_end);
            block[..prefix_end - block_start]
                .copy_from_slice(&self.aad_prefix.get()[block_start..prefix_end]);
        }

        let associated_start = block_start.max(prefix_len);
        let associated_end = block_end.min(data_end);
        if associated_start < associated_end {
            let destination_start = associated_start - block_start;
            let destination_end = associated_end - block_start;
            if let Err(error) =
                self.read_associated_data(&mut block[destination_start..destination_end])
            {
                self.finish(Err(error));
                return;
            }
        }

        self.aad_encoded_offset.set(block_end);
        self.xor_mac(&mut block);
        self.start_ecb_block(State::Mac, block);
    }

    fn start_mac_payload_block(&self) {
        let offset = self.payload_offset.get();
        let block_len = (self.len.get() - offset).min(BLOCK_SIZE);
        let mut block = [0; BLOCK_SIZE];
        let copied = self.workspace.map_or(false, |workspace| {
            block[..block_len].copy_from_slice(&workspace[offset..offset + block_len]);
            true
        });
        if !copied {
            self.finish(Err(ErrorCode::NOMEM));
            return;
        }

        self.payload_offset.set(offset + block_len);
        self.xor_mac(&mut block);
        self.start_ecb_block(State::Mac, block);
    }

    fn mac_block_done(&self, output: [u8; BLOCK_SIZE]) {
        self.mac.set(output);

        match self.mac_stage.get() {
            MacStage::B0 => {
                if self.aad_padded_len.get() > 0 {
                    self.mac_stage.set(MacStage::AssociatedData);
                    self.start_aad_block();
                } else if self.len.get() > 0 {
                    self.mac_stage.set(MacStage::Payload);
                    self.start_mac_payload_block();
                } else {
                    self.mac_done();
                }
            }
            MacStage::AssociatedData => {
                if self.aad_encoded_offset.get() < self.aad_padded_len.get() {
                    self.start_aad_block();
                } else if self.len.get() > 0 {
                    self.mac_stage.set(MacStage::Payload);
                    self.start_mac_payload_block();
                } else {
                    self.mac_done();
                }
            }
            MacStage::Payload => {
                if self.payload_offset.get() < self.len.get() {
                    self.start_mac_payload_block();
                } else {
                    self.mac_done();
                }
            }
        }
    }

    fn mac_done(&self) {
        match self.operation.get() {
            Operation::Encrypt => {
                self.tag.set(self.mac.get());
                self.start_tag();
            }
            Operation::Decrypt => {
                let mac = self.mac.get();
                let tag = self.tag.get();
                let mut difference = 0;
                for (mac_byte, tag_byte) in mac[..self.tag_len.get()].iter().zip(tag.iter()) {
                    difference |= mac_byte ^ tag_byte;
                }

                if difference == 0 {
                    self.write_output(self.len.get());
                } else {
                    self.finish(Err(ErrorCode::FAIL));
                }
            }
        }
    }

    fn counter_block(&self, counter: usize) -> [u8; BLOCK_SIZE] {
        let nonce_len = self.nonce_len.get();
        let length_bytes = BLOCK_SIZE - 1 - nonce_len;
        let mut block = [0; BLOCK_SIZE];
        block[0] = (length_bytes - 1) as u8;
        block[1..1 + nonce_len].copy_from_slice(&self.nonce.get()[..nonce_len]);
        Self::encode_length(&mut block, counter, length_bytes);
        block
    }

    fn start_tag(&self) {
        self.start_ecb_block(State::Tag, self.counter_block(0));
    }

    fn tag_block_done(&self, output: [u8; BLOCK_SIZE]) {
        let tag_len = self.tag_len.get();
        match self.operation.get() {
            Operation::Encrypt => {
                let tag = self.tag.get();
                let stored = self.workspace.map_or(false, |workspace| {
                    for index in 0..tag_len {
                        workspace[self.len.get() + index] = tag[index] ^ output[index];
                    }
                    true
                });
                if !stored {
                    self.finish(Err(ErrorCode::NOMEM));
                    return;
                }
            }
            Operation::Decrypt => {
                let mut tag = [0; BLOCK_SIZE];
                let loaded = self.workspace.map_or(false, |workspace| {
                    for index in 0..tag_len {
                        tag[index] = workspace[self.len.get() + index] ^ output[index];
                    }
                    true
                });
                if !loaded {
                    self.finish(Err(ErrorCode::NOMEM));
                    return;
                }
                self.tag.set(tag);
            }
        }

        self.payload_offset.set(0);
        if self.len.get() == 0 {
            self.payload_done();
        } else {
            self.start_ecb_block(State::Payload, self.counter_block(1));
        }
    }

    fn payload_block_done(&self, output: [u8; BLOCK_SIZE]) {
        let offset = self.payload_offset.get();
        let block_len = (self.len.get() - offset).min(BLOCK_SIZE);
        let updated = self.workspace.map_or(false, |workspace| {
            for index in 0..block_len {
                workspace[offset + index] ^= output[index];
            }
            true
        });
        if !updated {
            self.finish(Err(ErrorCode::NOMEM));
            return;
        }

        let next_offset = offset + block_len;
        self.payload_offset.set(next_offset);
        if next_offset == self.len.get() {
            self.payload_done();
        } else {
            let counter = next_offset / BLOCK_SIZE + 1;
            self.start_ecb_block(State::Payload, self.counter_block(counter));
        }
    }

    fn payload_done(&self) {
        match self.operation.get() {
            Operation::Encrypt => self.write_output(self.len.get() + self.tag_len.get()),
            Operation::Decrypt => self.start_mac(),
        }
    }

    fn write_output(&self, output_len: usize) {
        let result = self.client.map_or(Err(ErrorCode::OFF), |client| {
            self.workspace.map_or(Err(ErrorCode::NOMEM), |workspace| {
                client.write_output(&workspace[..output_len])
            })
        });
        self.finish(result);
    }

    fn finish(&self, result: Result<(), ErrorCode>) {
        if self.state.replace(State::Idle) == State::Idle {
            return;
        }

        self.ecb.take();
        self.client.map(|client| client.crypt_done(result));
    }
}

impl<E: Ecb<Aes128> + 'static> DriverMutexClient for SoftwareCcm<E> {
    fn ready(&'static self, resource: DriverMutexAny) {
        if self.state.get() != State::WaitingForEcb {
            return;
        }

        let ecb = match resource.downcast::<E>() {
            Ok(ecb) => ecb,
            Err(_) => {
                self.finish(Err(ErrorCode::INVAL));
                return;
            }
        };
        ecb.set_client(self);
        self.ecb.put(ecb);

        if let Err(error) = self.initialize() {
            self.finish(Err(error));
            return;
        }

        match self.operation.get() {
            Operation::Encrypt => self.start_mac(),
            Operation::Decrypt => self.start_tag(),
        }
    }
}

impl<E: Ecb<Aes128> + 'static> cipher::Ccm<Aes128> for SoftwareCcm<E> {
    fn crypt(
        &self,
        len: usize,
        associated_data_len: usize,
        tag_len: CcmTagLength,
        operation: Operation,
    ) -> Result<(), ErrorCode> {
        if self.state.get() != State::Idle {
            return Err(ErrorCode::BUSY);
        }
        if self.client.is_none() || self.ecb_handle.is_none() {
            return Err(ErrorCode::OFF);
        }

        let tag_len = tag_len.bytes();
        let workspace_len = len.checked_add(tag_len).ok_or(ErrorCode::SIZE)?;
        if self.workspace.map_or(0, |workspace| workspace.len()) < workspace_len {
            return Err(ErrorCode::SIZE);
        }

        let (aad_prefix, aad_prefix_len) = Self::aad_prefix(associated_data_len);
        let aad_padded_len = aad_prefix_len
            .checked_add(associated_data_len)
            .and_then(|length| length.checked_add(BLOCK_SIZE - 1))
            .map(|length| length / BLOCK_SIZE * BLOCK_SIZE)
            .ok_or(ErrorCode::SIZE)?;

        self.operation.set(operation);
        self.len.set(len);
        self.associated_data_len.set(associated_data_len);
        self.tag_len.set(tag_len);
        self.aad_prefix.set(aad_prefix);
        self.aad_prefix_len.set(aad_prefix_len);
        self.aad_padded_len.set(aad_padded_len);
        self.state.set(State::WaitingForEcb);

        let result = self
            .ecb_handle
            .map_or(Err(ErrorCode::OFF), |handle| self.ecb_mutex.request(handle));
        if let Err(error) = result {
            self.state.set(State::Idle);
            return Err(error);
        }

        Ok(())
    }

    fn set_client(&self, client: &'static dyn cipher::CcmClient<Aes128>) {
        self.client.set(client);
    }
}

impl<E: Ecb<Aes128> + 'static> cipher::EcbClient<Aes128> for SoftwareCcm<E> {
    fn read_key(&self, key: &mut [u8]) -> Result<(), ErrorCode> {
        if key.len() != KEY_SIZE {
            return Err(ErrorCode::SIZE);
        }
        key.copy_from_slice(&self.key.get());
        Ok(())
    }

    fn read_input(&self, input: &mut [u8]) -> Result<usize, ErrorCode> {
        let offset = self.ecb_input_offset.get();
        let read_len = input.len().min(BLOCK_SIZE - offset);
        if read_len == 0 {
            return Err(ErrorCode::INVAL);
        }
        input[..read_len].copy_from_slice(&self.ecb_input.get()[offset..offset + read_len]);
        self.ecb_input_offset.set(offset + read_len);
        Ok(read_len)
    }

    fn write_output(&self, output: &[u8]) -> Result<(), ErrorCode> {
        let offset = self.ecb_output_offset.get();
        if output.len() > BLOCK_SIZE - offset {
            return Err(ErrorCode::SIZE);
        }

        let mut block = self.ecb_output.get();
        block[offset..offset + output.len()].copy_from_slice(output);
        self.ecb_output.set(block);
        self.ecb_output_offset.set(offset + output.len());
        Ok(())
    }

    fn crypt_done(&self, result: Result<(), ErrorCode>) {
        if let Err(error) = result {
            self.finish(Err(error));
            return;
        }
        if self.ecb_input_offset.get() != BLOCK_SIZE || self.ecb_output_offset.get() != BLOCK_SIZE {
            self.finish(Err(ErrorCode::FAIL));
            return;
        }

        let output = self.ecb_output.get();
        match self.state.get() {
            State::Mac => self.mac_block_done(output),
            State::Tag => self.tag_block_done(output),
            State::Payload => self.payload_block_done(output),
            State::Idle | State::WaitingForEcb => self.finish(Err(ErrorCode::FAIL)),
        }
    }
}
