// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! Software implementation of AES-128 GCM over an ECB implementation.

use capsules_core::driver_mutex::{
    DriverMutex, DriverMutexAny, DriverMutexClient, DriverMutexHandle, DriverMutexRef,
};
use core::cell::Cell;
use kernel::ErrorCode;
use kernel::hil::crypto::cipher::{self, Aes128, Ecb, GcmTagLength, Operation};
use kernel::utilities::cells::{MapCell, OptionalCell};

const BLOCK_SIZE: usize = 16;
const KEY_SIZE: usize = 16;
const IV_SIZE: usize = 12;

#[derive(Clone, Copy, PartialEq)]
enum State {
    Idle,
    WaitingForEcb,
    HashKey,
    Payload,
    TagMask,
}

/// AES-128 GCM implemented in software using an encryption-only ECB driver.
///
/// The `workspace` passed to [`SoftwareGcm::new`] must be large enough to hold
/// the complete payload. Decryption retains plaintext there until the input tag
/// has been authenticated. A `SoftwareGcm` must be registered with its ECB
/// mutex using [`SoftwareGcm::register`] after placement in static memory.
pub struct SoftwareGcm<E: Ecb<Aes128> + 'static> {
    ecb_mutex: &'static DriverMutex<E>,
    ecb_handle: OptionalCell<DriverMutexHandle>,
    ecb: MapCell<DriverMutexRef<E>>,
    client: OptionalCell<&'static dyn cipher::GcmClient<Aes128>>,
    workspace: MapCell<&'static mut [u8]>,

    state: Cell<State>,
    operation: Cell<Operation>,
    len: Cell<usize>,
    associated_data_len: Cell<usize>,
    tag_len: Cell<usize>,
    offset: Cell<usize>,

    key: Cell<[u8; KEY_SIZE]>,
    iv: Cell<[u8; IV_SIZE]>,
    counter: Cell<[u8; BLOCK_SIZE]>,
    hash_key: Cell<[u8; BLOCK_SIZE]>,
    hash: Cell<[u8; BLOCK_SIZE]>,
    tag: Cell<[u8; BLOCK_SIZE]>,

    ecb_input: Cell<[u8; BLOCK_SIZE]>,
    ecb_input_offset: Cell<usize>,
    ecb_output: Cell<[u8; BLOCK_SIZE]>,
    ecb_output_offset: Cell<usize>,
}

impl<E: Ecb<Aes128> + 'static> SoftwareGcm<E> {
    /// Create a software GCM implementation over a mutex-protected ECB driver.
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
            offset: Cell::new(0),
            key: Cell::new([0; KEY_SIZE]),
            iv: Cell::new([0; IV_SIZE]),
            counter: Cell::new([0; BLOCK_SIZE]),
            hash_key: Cell::new([0; BLOCK_SIZE]),
            hash: Cell::new([0; BLOCK_SIZE]),
            tag: Cell::new([0; BLOCK_SIZE]),
            ecb_input: Cell::new([0; BLOCK_SIZE]),
            ecb_input_offset: Cell::new(0),
            ecb_output: Cell::new([0; BLOCK_SIZE]),
            ecb_output_offset: Cell::new(0),
        }
    }

    /// Register this GCM implementation as a client of its ECB mutex.
    pub fn register(&'static self) -> Result<(), ErrorCode> {
        if self.ecb_handle.is_some() {
            return Err(ErrorCode::ALREADY);
        }

        let handle = self.ecb_mutex.add_client(self).ok_or(ErrorCode::NOMEM)?;
        self.ecb_handle.set(handle);
        Ok(())
    }

    fn read_full_input(&self) -> Result<(), ErrorCode> {
        self.client.map_or(Err(ErrorCode::OFF), |client| {
            self.workspace.map_or(Err(ErrorCode::NOMEM), |workspace| {
                let mut offset = 0;
                while offset < self.len.get() {
                    let destination = &mut workspace[offset..self.len.get()];
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

    fn initialize(&self) -> Result<(), ErrorCode> {
        let mut key = [0; KEY_SIZE];
        let mut iv = [0; IV_SIZE];
        let mut tag = [0; BLOCK_SIZE];
        self.client.map_or(Err(ErrorCode::OFF), |client| {
            client.read_key(&mut key)?;
            client.read_iv(&mut iv)?;
            if self.operation.get() == Operation::Decrypt {
                client.read_tag(&mut tag[..self.tag_len.get()])?;
            }
            Ok(())
        })?;

        self.key.set(key);
        self.iv.set(iv);
        self.tag.set(tag);
        self.read_full_input()
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

    fn multiply(mut value: [u8; BLOCK_SIZE], mut factor: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let mut product = [0; BLOCK_SIZE];
        for _ in 0..128 {
            if value[0] & 0x80 != 0 {
                for (product_byte, factor_byte) in product.iter_mut().zip(factor.iter()) {
                    *product_byte ^= *factor_byte;
                }
            }

            let reduce = factor[BLOCK_SIZE - 1] & 1 != 0;
            let mut carry = 0;
            for byte in factor.iter_mut() {
                let next_carry = *byte & 1;
                *byte = (*byte >> 1) | (carry << 7);
                carry = next_carry;
            }
            if reduce {
                factor[0] ^= 0xe1;
            }

            let mut carry = 0;
            for byte in value.iter_mut().rev() {
                let next_carry = *byte >> 7;
                *byte = (*byte << 1) | carry;
                carry = next_carry;
            }
        }
        product
    }

    fn hash_block(&self, block: &[u8; BLOCK_SIZE]) {
        let mut value = self.hash.get();
        for (value_byte, block_byte) in value.iter_mut().zip(block.iter()) {
            *value_byte ^= *block_byte;
        }
        self.hash.set(Self::multiply(value, self.hash_key.get()));
    }

    fn hash_associated_data(&self) -> Result<(), ErrorCode> {
        let mut remaining = self.associated_data_len.get();
        while remaining > 0 {
            let block_len = remaining.min(BLOCK_SIZE);
            let mut block = [0; BLOCK_SIZE];
            let mut offset = 0;
            while offset < block_len {
                let read = self.client.map_or(Err(ErrorCode::OFF), |client| {
                    client.read_associated_data(&mut block[offset..block_len])
                })?;
                if read == 0 || read > block_len - offset {
                    return Err(ErrorCode::INVAL);
                }
                offset += read;
            }
            self.hash_block(&block);
            remaining -= block_len;
        }
        Ok(())
    }

    fn hash_payload(&self) -> Result<(), ErrorCode> {
        self.workspace.map_or(Err(ErrorCode::NOMEM), |workspace| {
            let mut offset = 0;
            while offset < self.len.get() {
                let block_len = (self.len.get() - offset).min(BLOCK_SIZE);
                let mut block = [0; BLOCK_SIZE];
                block[..block_len].copy_from_slice(&workspace[offset..offset + block_len]);
                self.hash_block(&block);
                offset += block_len;
            }
            Ok(())
        })
    }

    fn hash_lengths(&self) {
        let mut block = [0; BLOCK_SIZE];
        let associated_data_bits = (self.associated_data_len.get() as u64) * 8;
        let payload_bits = (self.len.get() as u64) * 8;
        block[..8].copy_from_slice(&associated_data_bits.to_be_bytes());
        block[8..].copy_from_slice(&payload_bits.to_be_bytes());
        self.hash_block(&block);
    }

    fn initial_counter(&self) -> [u8; BLOCK_SIZE] {
        let mut counter = [0; BLOCK_SIZE];
        counter[..IV_SIZE].copy_from_slice(&self.iv.get());
        counter[BLOCK_SIZE - 1] = 1;
        counter
    }

    fn increment_counter(&self) -> bool {
        let mut counter = self.counter.get();
        let value = u32::from_be_bytes(counter[IV_SIZE..].try_into().unwrap());
        let Some(value) = value.checked_add(1) else {
            return false;
        };
        counter[IV_SIZE..].copy_from_slice(&value.to_be_bytes());
        self.counter.set(counter);
        true
    }

    fn start_payload(&self) {
        self.offset.set(0);
        self.counter.set(self.initial_counter());
        if !self.increment_counter() {
            self.finish(Err(ErrorCode::SIZE));
            return;
        }
        self.start_ecb_block(State::Payload, self.counter.get());
    }

    fn payload_block_done(&self, keystream: [u8; BLOCK_SIZE]) {
        let offset = self.offset.get();
        let block_len = (self.len.get() - offset).min(BLOCK_SIZE);
        let updated = self.workspace.map_or(false, |workspace| {
            for index in 0..block_len {
                workspace[offset + index] ^= keystream[index];
            }
            true
        });
        if !updated {
            self.finish(Err(ErrorCode::NOMEM));
            return;
        }

        let next_offset = offset + block_len;
        self.offset.set(next_offset);
        if next_offset < self.len.get() {
            if self.increment_counter() {
                self.start_ecb_block(State::Payload, self.counter.get());
            } else {
                self.finish(Err(ErrorCode::SIZE));
            }
        } else if self.operation.get() == Operation::Encrypt {
            if let Err(error) = self.hash_payload() {
                self.finish(Err(error));
                return;
            }
            self.hash_lengths();
            self.start_tag_mask();
        } else {
            self.write_output();
        }
    }

    fn start_tag_mask(&self) {
        self.start_ecb_block(State::TagMask, self.initial_counter());
    }

    fn tag_mask_done(&self, mask: [u8; BLOCK_SIZE]) {
        let mut computed_tag = self.hash.get();
        for (tag_byte, mask_byte) in computed_tag.iter_mut().zip(mask.iter()) {
            *tag_byte ^= *mask_byte;
        }

        match self.operation.get() {
            Operation::Encrypt => {
                self.tag.set(computed_tag);
                self.write_output();
            }
            Operation::Decrypt => {
                let expected_tag = self.tag.get();
                let mut difference = 0;
                for index in 0..self.tag_len.get() {
                    difference |= computed_tag[index] ^ expected_tag[index];
                }
                if difference != 0 {
                    self.finish(Err(ErrorCode::FAIL));
                } else if self.len.get() == 0 {
                    self.write_output();
                } else {
                    self.start_payload();
                }
            }
        }
    }

    fn hash_key_done(&self, hash_key: [u8; BLOCK_SIZE]) {
        self.hash_key.set(hash_key);
        self.hash.set([0; BLOCK_SIZE]);
        if let Err(error) = self.hash_associated_data() {
            self.finish(Err(error));
            return;
        }

        match self.operation.get() {
            Operation::Encrypt if self.len.get() > 0 => self.start_payload(),
            Operation::Encrypt => {
                self.hash_lengths();
                self.start_tag_mask();
            }
            Operation::Decrypt => {
                if let Err(error) = self.hash_payload() {
                    self.finish(Err(error));
                    return;
                }
                self.hash_lengths();
                self.start_tag_mask();
            }
        }
    }

    fn write_output(&self) {
        let result = self.client.map_or(Err(ErrorCode::OFF), |client| {
            self.workspace.map_or(Err(ErrorCode::NOMEM), |workspace| {
                client.write_output(&workspace[..self.len.get()])?;
                if self.operation.get() == Operation::Encrypt {
                    client.write_tag(&self.tag.get()[..self.tag_len.get()])?;
                }
                Ok(())
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

impl<E: Ecb<Aes128> + 'static> DriverMutexClient for SoftwareGcm<E> {
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
        self.start_ecb_block(State::HashKey, [0; BLOCK_SIZE]);
    }
}

impl<E: Ecb<Aes128> + 'static> cipher::Gcm<Aes128> for SoftwareGcm<E> {
    fn crypt(
        &self,
        len: usize,
        associated_data_len: usize,
        tag_len: GcmTagLength,
        operation: Operation,
    ) -> Result<(), ErrorCode> {
        if self.state.get() != State::Idle {
            return Err(ErrorCode::BUSY);
        }
        if self.client.is_none() || self.ecb_handle.is_none() {
            return Err(ErrorCode::OFF);
        }
        if self.workspace.map_or(0, |workspace| workspace.len()) < len {
            return Err(ErrorCode::SIZE);
        }
        if len > (u64::MAX / 8) as usize || associated_data_len > (u64::MAX / 8) as usize {
            return Err(ErrorCode::SIZE);
        }
        if len.div_ceil(BLOCK_SIZE) > u32::MAX as usize - 1 {
            return Err(ErrorCode::SIZE);
        }

        self.len.set(len);
        self.associated_data_len.set(associated_data_len);
        self.tag_len.set(tag_len.bytes());
        self.operation.set(operation);
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

    fn set_client(&self, client: &'static dyn cipher::GcmClient<Aes128>) {
        self.client.set(client);
    }
}

impl<E: Ecb<Aes128> + 'static> cipher::EcbClient<Aes128> for SoftwareGcm<E> {
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
            State::HashKey => self.hash_key_done(output),
            State::Payload => self.payload_block_done(output),
            State::TagMask => self.tag_mask_done(output),
            State::Idle | State::WaitingForEcb => self.finish(Err(ErrorCode::FAIL)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ghash_nist_zero_key_block() {
        let hash_key = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let ciphertext = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
            0xfe, 0x78,
        ];
        let ciphertext_hash = [
            0x5e, 0x2e, 0xc7, 0x46, 0x91, 0x70, 0x62, 0x88, 0x2c, 0x85, 0xb0, 0x68, 0x53, 0x53,
            0xde, 0xb7,
        ];

        assert_eq!(
            SoftwareGcm::<TestEcb>::multiply(ciphertext, hash_key),
            ciphertext_hash
        );

        let mut length_block = [0; BLOCK_SIZE];
        length_block[8..].copy_from_slice(&128_u64.to_be_bytes());
        for (byte, length_byte) in length_block.iter_mut().zip(ciphertext_hash) {
            *byte ^= length_byte;
        }
        assert_eq!(
            SoftwareGcm::<TestEcb>::multiply(length_block, hash_key),
            [
                0xf3, 0x8c, 0xbb, 0x1a, 0xd6, 0x92, 0x23, 0xdc, 0xc3, 0x45, 0x7a, 0xe5, 0xb6, 0xb0,
                0xf8, 0x85,
            ]
        );

        let tag_mask = [
            0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
            0x45, 0x5a,
        ];
        let mut tag = SoftwareGcm::<TestEcb>::multiply(length_block, hash_key);
        for (tag_byte, mask_byte) in tag.iter_mut().zip(tag_mask) {
            *tag_byte ^= mask_byte;
        }
        assert_eq!(
            tag,
            [
                0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57,
                0xbd, 0xdf,
            ]
        );
    }

    struct TestEcb;

    impl Ecb<Aes128> for TestEcb {
        fn crypt(&self, _len: usize, _operation: Operation) -> Result<(), ErrorCode> {
            unimplemented!()
        }

        fn set_client(&self, _client: &'static dyn cipher::EcbClient<Aes128>) {}
    }
}
