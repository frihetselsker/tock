// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! Software implementation of AES-128 CBC over an ECB implementation.

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

/// AES-128 CBC implemented in software over an ECB driver.
///
/// CBC decryption is available only when the underlying ECB driver supports
/// decryption. The `workspace` passed to [`SoftwareCbc::new`] must be large
/// enough to hold the complete input. A `SoftwareCbc` must be registered with
/// its ECB mutex using [`SoftwareCbc::register`] after placement in static
/// memory.
pub struct SoftwareCbc<E: Ecb<Aes128> + 'static> {
    ecb_mutex: &'static DriverMutex<E>,
    ecb_handle: OptionalCell<DriverMutexHandle>,
    ecb: MapCell<DriverMutexRef<E>>,
    client: OptionalCell<&'static dyn cipher::CbcClient<Aes128>>,
    workspace: MapCell<&'static mut [u8]>,

    state: Cell<State>,
    operation: Cell<Operation>,
    len: Cell<usize>,
    offset: Cell<usize>,
    key: Cell<[u8; KEY_SIZE]>,
    chaining_value: Cell<[u8; BLOCK_SIZE]>,

    ecb_input: Cell<[u8; BLOCK_SIZE]>,
    ecb_input_offset: Cell<usize>,
    ecb_output: Cell<[u8; BLOCK_SIZE]>,
    ecb_output_offset: Cell<usize>,
}

impl<E: Ecb<Aes128> + 'static> SoftwareCbc<E> {
    /// Create a software CBC implementation over a mutex-protected ECB driver.
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
            offset: Cell::new(0),
            key: Cell::new([0; KEY_SIZE]),
            chaining_value: Cell::new([0; BLOCK_SIZE]),
            ecb_input: Cell::new([0; BLOCK_SIZE]),
            ecb_input_offset: Cell::new(0),
            ecb_output: Cell::new([0; BLOCK_SIZE]),
            ecb_output_offset: Cell::new(0),
        }
    }

    /// Register this CBC implementation as a client of its ECB mutex.
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
        let mut iv = [0; BLOCK_SIZE];
        self.client.map_or(Err(ErrorCode::OFF), |client| {
            client.read_key(&mut key)?;
            client.read_iv(&mut iv)?;
            Ok(())
        })?;

        self.key.set(key);
        self.chaining_value.set(iv);
        self.offset.set(0);
        self.read_full_input()
    }

    fn start_block(&self) {
        let offset = self.offset.get();
        let mut input = [0; BLOCK_SIZE];
        let loaded = self.workspace.map_or(false, |workspace| {
            input.copy_from_slice(&workspace[offset..offset + BLOCK_SIZE]);
            true
        });
        if !loaded {
            self.finish(Err(ErrorCode::NOMEM));
            return;
        }

        if self.operation.get() == Operation::Encrypt {
            for (byte, chain_byte) in input.iter_mut().zip(self.chaining_value.get().iter()) {
                *byte ^= *chain_byte;
            }
        }

        self.ecb_input.set(input);
        self.ecb_input_offset.set(0);
        self.ecb_output.set([0; BLOCK_SIZE]);
        self.ecb_output_offset.set(0);
        let result = self.ecb.map_or(Err(ErrorCode::FAIL), |ecb| {
            ecb.crypt(BLOCK_SIZE, self.operation.get())
        });
        if let Err(error) = result {
            self.finish(Err(error));
        }
    }

    fn block_done(&self) {
        let offset = self.offset.get();
        let input = self.ecb_input.get();
        let mut output = self.ecb_output.get();
        let next_chain = match self.operation.get() {
            Operation::Encrypt => output,
            Operation::Decrypt => {
                for (byte, chain_byte) in output.iter_mut().zip(self.chaining_value.get().iter()) {
                    *byte ^= *chain_byte;
                }
                input
            }
        };

        let stored = self.workspace.map_or(false, |workspace| {
            workspace[offset..offset + BLOCK_SIZE].copy_from_slice(&output);
            true
        });
        if !stored {
            self.finish(Err(ErrorCode::NOMEM));
            return;
        }

        self.chaining_value.set(next_chain);
        let next_offset = offset + BLOCK_SIZE;
        self.offset.set(next_offset);
        if next_offset == self.len.get() {
            self.write_output();
        } else {
            self.start_block();
        }
    }

    fn write_output(&self) {
        let result = self.client.map_or(Err(ErrorCode::OFF), |client| {
            self.workspace.map_or(Err(ErrorCode::NOMEM), |workspace| {
                client.write_output(&workspace[..self.len.get()])?;
                client.write_iv(&self.chaining_value.get())
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

impl<E: Ecb<Aes128> + 'static> DriverMutexClient for SoftwareCbc<E> {
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

impl<E: Ecb<Aes128> + 'static> cipher::Cbc<Aes128> for SoftwareCbc<E> {
    fn crypt(&self, len: usize, operation: Operation) -> Result<(), ErrorCode> {
        if self.state.get() != State::Idle {
            return Err(ErrorCode::BUSY);
        }
        if self.client.is_none() || self.ecb_handle.is_none() {
            return Err(ErrorCode::OFF);
        }
        if !len.is_multiple_of(BLOCK_SIZE) {
            return Err(ErrorCode::INVAL);
        }
        if self.workspace.map_or(0, |workspace| workspace.len()) < len {
            return Err(ErrorCode::SIZE);
        }

        self.len.set(len);
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

    fn set_client(&self, client: &'static dyn cipher::CbcClient<Aes128>) {
        self.client.set(client);
    }
}

impl<E: Ecb<Aes128> + 'static> cipher::EcbClient<Aes128> for SoftwareCbc<E> {
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

        match self.state.get() {
            State::Crypt => self.block_done(),
            State::Idle | State::WaitingForEcb => self.finish(Err(ErrorCode::FAIL)),
        }
    }
}
