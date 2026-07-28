// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! Software implementation of AES-128 CTR over an ECB implementation.

use capsules_core::driver_mutex::{
    DriverMutex, DriverMutexAny, DriverMutexClient, DriverMutexHandle, DriverMutexRef,
};
use core::cell::Cell;
use kernel::ErrorCode;
use kernel::hil::crypto::cipher::{self, Aes128, Ecb, Operation};
use kernel::utilities::cells::{MapCell, OptionalCell};

const BLOCK_SIZE: usize = 16;
const KEY_SIZE: usize = 16;

#[derive(Clone, Copy, PartialEq)]
enum State {
    Idle,
    WaitingForEcb,
    Crypt,
}

/// AES-128 CTR implemented in software using an encryption-only ECB driver.
///
/// The `workspace` passed to [`SoftwareCtr::new`] must be large enough to hold
/// the complete input. A `SoftwareCtr` must be registered with its ECB mutex
/// using [`SoftwareCtr::register`] after it has been placed in static memory.
pub struct SoftwareCtr<E: Ecb<Aes128> + 'static> {
    ecb_mutex: &'static DriverMutex<E>,
    ecb_handle: OptionalCell<DriverMutexHandle>,
    ecb: MapCell<DriverMutexRef<E>>,
    client: OptionalCell<&'static dyn cipher::CtrClient<Aes128>>,
    workspace: MapCell<&'static mut [u8]>,

    state: Cell<State>,
    len: Cell<usize>,
    offset: Cell<usize>,
    key: Cell<[u8; KEY_SIZE]>,
    counter: Cell<[u8; BLOCK_SIZE]>,
    counter_start: Cell<usize>,

    ecb_input_offset: Cell<usize>,
    ecb_output: Cell<[u8; BLOCK_SIZE]>,
    ecb_output_offset: Cell<usize>,
}

impl<E: Ecb<Aes128> + 'static> SoftwareCtr<E> {
    /// Create a software CTR implementation over a mutex-protected ECB driver.
    pub fn new(ecb_mutex: &'static DriverMutex<E>, workspace: &'static mut [u8]) -> Self {
        Self {
            ecb_mutex,
            ecb_handle: OptionalCell::empty(),
            ecb: MapCell::empty(),
            client: OptionalCell::empty(),
            workspace: MapCell::new(workspace),
            state: Cell::new(State::Idle),
            len: Cell::new(0),
            offset: Cell::new(0),
            key: Cell::new([0; KEY_SIZE]),
            counter: Cell::new([0; BLOCK_SIZE]),
            counter_start: Cell::new(0),
            ecb_input_offset: Cell::new(0),
            ecb_output: Cell::new([0; BLOCK_SIZE]),
            ecb_output_offset: Cell::new(0),
        }
    }

    /// Register this CTR implementation as a client of its ECB mutex.
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

    fn counter_can_advance(counter: &[u8], increments: usize) -> bool {
        let mut carry = increments;
        for byte in counter.iter().rev() {
            let sum = usize::from(*byte) + (carry & 0xff);
            carry = (carry >> 8) + (sum >> 8);
        }
        carry == 0
    }

    fn increment_counter(&self) -> bool {
        let mut counter = self.counter.get();
        for byte in counter[self.counter_start.get()..].iter_mut().rev() {
            let (value, overflow) = byte.overflowing_add(1);
            *byte = value;
            if !overflow {
                self.counter.set(counter);
                return true;
            }
        }
        false
    }

    fn initialize(&self) -> Result<(), ErrorCode> {
        let mut key = [0; KEY_SIZE];
        let mut counter = [0; BLOCK_SIZE];
        let (nonce_len, counter_len) = self.client.map_or(Err(ErrorCode::OFF), |client| {
            client.read_key(&mut key)?;
            let nonce_len = client.read_nonce(&mut counter)?;
            if nonce_len >= BLOCK_SIZE {
                return Err(ErrorCode::INVAL);
            }
            let counter_len = client.read_counter(&mut counter[nonce_len..])?;
            Ok((nonce_len, counter_len))
        })?;

        if counter_len == 0 || nonce_len + counter_len != BLOCK_SIZE {
            return Err(ErrorCode::INVAL);
        }

        let blocks = self.len.get().div_ceil(BLOCK_SIZE);
        if blocks > 0 && !Self::counter_can_advance(&counter[nonce_len..], blocks.saturating_sub(1))
        {
            return Err(ErrorCode::SIZE);
        }

        self.key.set(key);
        self.counter.set(counter);
        self.counter_start.set(nonce_len);
        self.offset.set(0);
        self.read_full_input()
    }

    fn start_block(&self) {
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

    fn block_done(&self) {
        let offset = self.offset.get();
        let block_len = (self.len.get() - offset).min(BLOCK_SIZE);
        let output = self.ecb_output.get();
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
        self.offset.set(next_offset);
        if next_offset == self.len.get() {
            self.write_output();
        } else if self.increment_counter() {
            self.start_block();
        } else {
            self.finish(Err(ErrorCode::SIZE));
        }
    }

    fn write_output(&self) {
        let result = self.client.map_or(Err(ErrorCode::OFF), |client| {
            self.workspace.map_or(Err(ErrorCode::NOMEM), |workspace| {
                client.write_output(&workspace[..self.len.get()])
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

impl<E: Ecb<Aes128> + 'static> DriverMutexClient for SoftwareCtr<E> {
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
        } else if self.len.get() == 0 {
            self.write_output();
        } else {
            self.state.set(State::Crypt);
            self.start_block();
        }
    }
}

impl<E: Ecb<Aes128> + 'static> cipher::Ctr<Aes128> for SoftwareCtr<E> {
    fn crypt(&self, len: usize, _operation: Operation) -> Result<(), ErrorCode> {
        if self.state.get() != State::Idle {
            return Err(ErrorCode::BUSY);
        }
        if self.client.is_none() || self.ecb_handle.is_none() {
            return Err(ErrorCode::OFF);
        }
        if self.workspace.map_or(0, |workspace| workspace.len()) < len {
            return Err(ErrorCode::SIZE);
        }

        self.len.set(len);
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

    fn set_client(&self, client: &'static dyn cipher::CtrClient<Aes128>) {
        self.client.set(client);
    }
}

impl<E: Ecb<Aes128> + 'static> cipher::EcbClient<Aes128> for SoftwareCtr<E> {
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
        input[..read_len].copy_from_slice(&self.counter.get()[offset..offset + read_len]);
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

        match self.state.get() {
            State::Crypt => self.block_done(),
            State::Idle | State::WaitingForEcb => self.finish(Err(ErrorCode::FAIL)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_capacity_rejects_wrap() {
        assert!(SoftwareCtr::<TestEcb>::counter_can_advance(&[0xfe], 1));
        assert!(!SoftwareCtr::<TestEcb>::counter_can_advance(&[0xff], 1));
        assert!(SoftwareCtr::<TestEcb>::counter_can_advance(
            &[0xfe, 0xff],
            0x100
        ));
        assert!(!SoftwareCtr::<TestEcb>::counter_can_advance(
            &[0xff, 0x00],
            0x100
        ));
    }

    struct TestEcb;

    impl Ecb<Aes128> for TestEcb {
        fn crypt(&self, _len: usize, _operation: Operation) -> Result<(), ErrorCode> {
            unimplemented!()
        }

        fn set_client(&self, _client: &'static dyn cipher::EcbClient<Aes128>) {}
    }
}
