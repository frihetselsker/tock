// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! Syscall driver for HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
//!
//! # System call interface
//!
//! ## `subscribe_num`
//!
//! - `0`: operation completion. Callback arguments are `(status, 0, 0)`.
//!
//! ## Read-only allow buffers
//!
//! - `0`: salt
//! - `1`: initial key material (ikm)
//! - `2`: info
//!
//! ## Read-write allow buffers
//!
//! - `0`: pseudorandom key (prk)
//! - `1`: output keying material (okm)
//!
//! ## Commands
//!
//! - `0`: existence check
//! - `1`: perform an HKDF operation. `data1` is the algorithm. `data2` is the size of salt.
//!
//! Mode values are `0 = Md5`, `1 = Sha1`, `2 = Sha224`, `3 = Sha256`, `4 = Sha384`, `5 = Sha512`, `6 = Sha512-224`, and `7 = Sha512-256`.

use core::cell::Cell;

use capsules_core::driver;
use capsules_core::driver_mutex::{
    DriverMutex, DriverMutexAny, DriverMutexClient, DriverMutexHandle, DriverMutexRef,
};
use kernel::errorcode::into_statuscode;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, GrantKernelData, UpcallCount};
use kernel::hil::crypto;
use kernel::hil::crypto::digest::{Algorithm, Client, HmacClient};
use kernel::processbuffer::{ReadableProcessBuffer, ReadableProcessSlice, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::{MapCell, OptionalCell};
use kernel::{ErrorCode, ProcessId};

/// Syscall driver number.
pub const DRIVER_NUM: usize = driver::NUM::Hmac as usize;

/// Upcalls for HKDF operation completing.
mod upcall {
    pub const DONE: usize = 0;
    pub const COUNT: u8 = 1;
}

/// Ids for read-only allow buffers
mod ro_allow {
    pub const SALT: usize = 0;
    pub const IKM: usize = 1;
    pub const INFO: usize = 2;
    /// The number of allow buffers the kernel stores for this grant
    pub const COUNT: u8 = 3;
}

/// Ids for read-write allow buffers
mod rw_allow {
    pub const PRK: usize = 0;
    pub const OKM: usize = 1;
    /// The number of allow buffers the kernel stores for this grant
    pub const COUNT: u8 = 1;
}

#[derive(Clone, Copy)]
enum State {
    Idle,
    Waiting {
        processid: ProcessId,
        algorithm: Algorithm,
    },
    Active {
        processid: ProcessId,
        algorithm: Algorithm,
        stage: Stage,
    },
}

#[derive(Clone, Copy)]
enum Stage {
    Extract,
    Expand {
        iteration: usize,
        t_len: usize,
        substage: Substage,
    },
}

#[derive(Clone, Copy)]
enum Substage {
    T,
    Info,
    Index,
}

#[derive(Clone, Copy)]
enum KeyState {
    InnerKey,
    OuterKey,
}

impl KeyState {
    pub fn update(self) -> Option<Self> {
        match self {
            KeyState::InnerKey => Some(KeyState::OuterKey),
            KeyState::OuterKey => None,
        }
    }
}

enum BufferType {
    ReadOnly,
    ReadWrite,
}

fn parse_algorithm(value: usize) -> Result<Algorithm, ErrorCode> {
    match value {
        0 => Ok(Algorithm::Md5),
        1 => Ok(Algorithm::Sha1),
        2 => Ok(Algorithm::Sha224),
        3 => Ok(Algorithm::Sha256),
        4 => Ok(Algorithm::Sha384),
        5 => Ok(Algorithm::Sha512),
        6 => Ok(Algorithm::Sha512_224),
        7 => Ok(Algorithm::Sha512_256),
        _ => Err(ErrorCode::INVAL),
    }
}

fn readonly_buffer_len(
    kernel_data: &GrantKernelData<'_>,
    number: usize,
) -> Result<usize, ErrorCode> {
    kernel_data
        .get_readonly_processbuffer(number)
        .map(|buffer| buffer.len())
        .map_err(|error| error.into())
}

fn readwrite_buffer_len(
    kernel_data: &GrantKernelData<'_>,
    number: usize,
) -> Result<usize, ErrorCode> {
    kernel_data
        .get_readwrite_processbuffer(number)
        .map(|buffer| buffer.len())
        .map_err(|error| error.into())
}

pub struct Hkdf<H: crypto::digest::Hmac + 'static> {
    hmac_mutex: &'static DriverMutex<H>,
    hmac_handle: OptionalCell<DriverMutexHandle>,
    hmac: MapCell<DriverMutexRef<H>>,
    apps: Grant<
        (),
        UpcallCount<{ upcall::COUNT }>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
    state: Cell<State>,
    key_state: OptionalCell<KeyState>,
    num_of_iterations: Cell<usize>,
    ikm_len: Cell<usize>,
    salt_len: Cell<usize>,
    prk_len: Cell<usize>,
    info_len: Cell<usize>,
    okm_len: Cell<usize>,
    ikm_offset: Cell<usize>,
    salt_offset: Cell<usize>,
    prk_offset: Cell<usize>,
    info_offset: Cell<usize>,
    okm_offset: Cell<usize>,
}

impl<H: crypto::digest::Hmac> Hkdf<H> {
    pub fn new(
        hmac_mutex: &'static DriverMutex<H>,
        apps: Grant<
            (),
            UpcallCount<{ upcall::COUNT }>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
    ) -> Hkdf<H> {
        Hkdf {
            hmac_mutex,
            hmac_handle: OptionalCell::empty(),
            hmac: MapCell::empty(),
            apps,
            state: Cell::new(State::Idle),
            key_state: OptionalCell::empty(),
            num_of_iterations: Cell::new(0),
            ikm_len: Cell::new(0),
            salt_len: Cell::new(0),
            prk_len: Cell::new(0),
            info_len: Cell::new(0),
            okm_len: Cell::new(0),
            ikm_offset: Cell::new(0),
            salt_offset: Cell::new(0),
            prk_offset: Cell::new(0),
            info_offset: Cell::new(0),
            okm_offset: Cell::new(0),
        }
    }

    pub fn register(&'static self) -> Result<(), ErrorCode> {
        if self.hmac_handle.is_some() {
            return Err(ErrorCode::ALREADY);
        }

        let hmac_handle = self.hmac_mutex.add_client(self).ok_or(ErrorCode::NOMEM)?;
        self.hmac_handle.set(hmac_handle);
        Ok(())
    }

    fn active_processid(&self) -> Result<ProcessId, ErrorCode> {
        match self.state.get() {
            State::Active { processid, .. } => Ok(processid),
            State::Idle | State::Waiting { .. } => Err(ErrorCode::RESERVE),
        }
    }

    fn reset_expand_offsets(&self) {
        self.info_offset.take();
        self.okm_offset.take();
        self.key_state.set(KeyState::InnerKey);
    }

    fn read_at(
        &self,
        allow_number: usize,
        buffer_type: BufferType,
        offset: usize,
        destination: &mut [u8],
    ) -> Result<usize, ErrorCode> {
        let processid = self.active_processid()?;
        let reader_fn = |source: &ReadableProcessSlice| {
            if offset >= source.len() || destination.is_empty() {
                return Err(ErrorCode::SIZE);
            }
            let read_len = destination.len().min(source.len() - offset);
            source[offset..offset + read_len].copy_to_slice(&mut destination[..read_len]);
            Ok(read_len)
        };

        match buffer_type {
            BufferType::ReadOnly => self
                .apps
                .enter(processid, |_, kernel_data| {
                    kernel_data
                        .get_readonly_processbuffer(allow_number)
                        .and_then(|buffer| buffer.enter(reader_fn))
                        .unwrap_or(Err(ErrorCode::RESERVE))
                })
                .unwrap_or_else(|error| Err(error.into())),
            BufferType::ReadWrite => self
                .apps
                .enter(processid, |_, kernel_data| {
                    kernel_data
                        .get_readwrite_processbuffer(allow_number)
                        .and_then(|buffer| buffer.enter(reader_fn))
                        .unwrap_or(Err(ErrorCode::RESERVE))
                })
                .unwrap_or_else(|error| Err(error.into())),
        }
    }

    fn read_ikm(&self, destination: &mut [u8]) -> Result<usize, ErrorCode> {
        let offset = self.ikm_offset.get();
        let read = self.read_at(ro_allow::IKM, BufferType::ReadOnly, offset, destination)?;
        self.ikm_offset.set(offset + read);
        Ok(read)
    }

    fn read_salt(&self, destination: &mut [u8]) -> Result<usize, ErrorCode> {
        if self.key_state.is_some() {
            let offset = self.salt_offset.get();
            let read = self.read_at(ro_allow::SALT, BufferType::ReadOnly, offset, destination)?;
            let updated_offset = offset + read;
            if updated_offset == self.salt_len.get() {
                self.salt_offset.take();
            } else {
                self.salt_offset.set(updated_offset);
            }
            self.key_state.map_or(None, |key_state| key_state.update());
            Ok(read)
        } else {
            Err(ErrorCode::ALREADY)
        }
    }

    fn read_info(&self, destination: &mut [u8]) -> Result<usize, ErrorCode> {
        let offset = self.info_offset.get();
        let read = self.read_at(ro_allow::INFO, BufferType::ReadOnly, offset, destination)?;
        self.info_offset.set(offset + read);
        Ok(read)
    }

    fn read_index(&self, index: u8, destination: &mut [u8]) -> Result<usize, ErrorCode> {
        if destination.is_empty() {
            return Err(ErrorCode::SIZE);
        }
        destination[0] = index;
        Ok(1)
    }

    fn read_okm(&self, destination: &mut [u8]) -> Result<usize, ErrorCode> {
        let offset = self.okm_offset.get();
        let read = self.read_at(rw_allow::OKM, BufferType::ReadWrite, offset, destination)?;
        self.okm_offset.set(offset + read);
        Ok(read)
    }

    fn read_prk(&self, destination: &mut [u8]) -> Result<usize, ErrorCode> {
        if self.key_state.is_some() {
            let offset = self.prk_offset.get();
            let read = self.read_at(rw_allow::PRK, BufferType::ReadWrite, offset, destination)?;
            let updated_offset = offset + read;
            if updated_offset == self.prk_len.get() {
                self.prk_offset.take();
            } else {
                self.prk_offset.set(updated_offset);
            }
            self.key_state.map_or(None, |key_state| key_state.update());
            Ok(read)
        } else {
            Err(ErrorCode::ALREADY)
        }
    }

    fn write_at(&self, allow_number: usize, offset: usize, source: &[u8]) -> Result<(), ErrorCode> {
        let processid = self.active_processid()?;
        self.apps
            .enter(processid, |_, kernel_data| {
                kernel_data
                    .get_readwrite_processbuffer(allow_number)
                    .and_then(|buffer| {
                        buffer.mut_enter(|destination| {
                            let end = offset.checked_add(source.len()).ok_or(ErrorCode::SIZE)?;
                            if end > destination.len() {
                                return Err(ErrorCode::SIZE);
                            }
                            destination[offset..end].copy_from_slice(source);
                            Ok(())
                        })
                    })
                    .unwrap_or(Err(ErrorCode::RESERVE))
            })
            .unwrap_or_else(|error| Err(error.into()))
    }

    fn write_okm(&self, source: &[u8]) -> Result<(), ErrorCode> {
        let offset = self.okm_offset.get();
        if offset < self.okm_len.get() {
            self.write_at(rw_allow::OKM, offset, source)?;
            self.okm_offset.set(offset + source.len());
        }
        Ok(())
    }

    fn write_prk(&self, source: &[u8]) -> Result<(), ErrorCode> {
        let offset = self.prk_offset.get();
        self.write_at(rw_allow::PRK, offset, source)?;
        self.prk_offset.set(offset + source.len());
        Ok(())
    }

    fn start_operation(&self, processid: ProcessId, algo_value: usize) -> Result<(), ErrorCode> {
        if !matches!(self.state.get(), State::Idle) {
            return Err(ErrorCode::BUSY);
        }
        if self.hmac_handle.is_none() {
            return Err(ErrorCode::OFF);
        }

        let algorithm = parse_algorithm(algo_value)?;
        let (salt_len, ikm_len, prk_len, info_len, okm_len) = self.apps.enter(
            processid,
            |_, kernel_data| -> Result<(usize, usize, usize, usize, usize), ErrorCode> {
                let salt_len = readonly_buffer_len(kernel_data, ro_allow::SALT)?;
                if salt_len > algorithm.get_block_size() {
                    return Err(ErrorCode::INVAL);
                }
                let ikm_len = readonly_buffer_len(kernel_data, ro_allow::IKM)?;
                let prk_len = readwrite_buffer_len(kernel_data, rw_allow::PRK)?;
                if prk_len != algorithm.get_digest_len() {
                    return Err(ErrorCode::INVAL);
                }
                let info_len = readonly_buffer_len(kernel_data, ro_allow::INFO)?;
                let okm_len = readwrite_buffer_len(kernel_data, rw_allow::OKM)?;

                Ok((salt_len, ikm_len, prk_len, info_len, okm_len))
            },
        )??;

        self.salt_len.set(salt_len);
        self.ikm_len.set(ikm_len);
        self.prk_len.set(prk_len);
        self.info_len.set(info_len);
        self.okm_len.set(okm_len);
        self.salt_offset.set(0);
        self.ikm_offset.set(0);
        self.prk_offset.set(0);
        self.info_offset.set(0);
        self.okm_offset.set(0);
        //  N = ceil(L / HashLen)
        self.num_of_iterations.set(okm_len.div_ceil(prk_len));
        self.key_state.set(KeyState::InnerKey);
        self.state.set(State::Waiting {
            processid,
            algorithm,
        });

        if let Err(error) = self.hmac_handle.map_or(Err(ErrorCode::OFF), |handle| {
            self.hmac_mutex.request(handle)
        }) {
            self.state.set(State::Idle);
            return Err(error);
        }
        Ok(())
    }

    fn finish(&self, result: Result<(), ErrorCode>) {
        let state = self.state.replace(State::Idle);
        self.hmac.take().inspect(|hmac| {
            hmac.clear_data();
        });

        let processid = match state {
            State::Waiting { processid, .. } | State::Active { processid, .. } => processid,
            State::Idle => return,
        };
        let _ = self.apps.enter(processid, |_, kernel_data| {
            let _ = kernel_data.schedule_upcall(upcall::DONE, (into_statuscode(result), 0, 0));
        });
    }
}

impl<H: crypto::digest::Hmac> DriverMutexClient for Hkdf<H> {
    fn ready(&'static self, resource: DriverMutexAny) {
        let (processid, algorithm) = match self.state.get() {
            State::Waiting {
                processid,
                algorithm,
            } => (processid, algorithm),
            State::Idle | State::Active { .. } => return,
        };
        self.state.set(State::Active {
            processid,
            algorithm,
            stage: Stage::Extract,
        });

        let result = match resource.downcast::<H>() {
            Ok(hmac) => {
                hmac.set_client(self);
                self.hmac.put(hmac);
                self.hmac.map_or(Err(ErrorCode::FAIL), |hmac| {
                    if self.salt_len.get() == 0 {
                        hmac.hash(algorithm, self.ikm_len.get())
                    } else {
                        hmac.authenticate(algorithm, self.ikm_len.get(), self.salt_len.get())
                    }
                })
            }
            Err(_) => Err(ErrorCode::INVAL),
        };

        if let Err(error) = result {
            self.finish(Err(error));
        }
    }
}

impl<H: crypto::digest::Hmac> Client for Hkdf<H> {
    fn read_input(&self, input: &mut [u8]) -> Result<usize, ErrorCode> {
        if let State::Active { stage, .. } = self.state.get() {
            match stage {
                Stage::Extract => self.read_ikm(input),
                Stage::Expand {
                    iteration,
                    t_len,
                    substage,
                } => {
                    // Try your best to write all the data packed in `input`
                    let mut offset = 0;
                    let mut substage = substage;
                    loop {
                        match substage {
                            Substage::T => {
                                let ceil = input.len().min(t_len);
                                self.read_okm(&mut input[..ceil])?;
                                substage = Substage::Info;
                                offset += ceil;
                                if offset == input.len() {
                                    break;
                                }
                            }
                            Substage::Info => {
                                let ceil = (input.len() - offset).min(self.info_len.get());
                                self.read_info(&mut input[offset..ceil])?;
                                offset += ceil;
                                substage = Substage::Index;
                                if offset == input.len() {
                                    break;
                                }
                            }
                            Substage::Index => {
                                self.read_index(iteration as u8, &mut input[offset..])?;
                                offset += 1;
                                break;
                            }
                        }
                    }
                    self.okm_offset.set(offset);
                    Ok(offset)
                }
            }
        } else {
            unreachable!()
        }
    }

    fn write_output(&self, output: &[u8]) -> Result<(), ErrorCode> {
        if let State::Active { stage, .. } = self.state.get() {
            match stage {
                Stage::Extract => self.write_prk(output),
                Stage::Expand { .. } => self.write_okm(output),
            }
        } else {
            unreachable!()
        }
    }

    fn hash_done(&self, result: Result<(), ErrorCode>) {
        if let State::Active {
            stage,
            processid,
            algorithm,
        } = self.state.get()
        {
            if result.is_err() {
                self.finish(result);
            } else {
                match stage {
                    Stage::Extract => {
                        self.reset_expand_offsets();
                        self.state.set(State::Active {
                            stage: Stage::Expand {
                                iteration: 1,
                                t_len: 0,
                                substage: Substage::Info,
                            },
                            processid,
                            algorithm,
                        });
                        let result = self.hmac.map_or(Err(ErrorCode::FAIL), |hmac| {
                            hmac.authenticate(
                                algorithm,
                                self.info_len.get() + 1,
                                self.prk_len.get(),
                            )
                        });
                        if result.is_err() {
                            self.finish(result);
                        }
                    }
                    Stage::Expand { iteration, .. }
                        if iteration == self.num_of_iterations.get() =>
                    {
                        self.finish(result)
                    }
                    Stage::Expand {
                        iteration, t_len, ..
                    } => {
                        self.reset_expand_offsets();
                        self.state.set(State::Active {
                            stage: Stage::Expand {
                                iteration: iteration + 1,
                                t_len: t_len + self.prk_len.get(),
                                substage: Substage::T,
                            },
                            processid,
                            algorithm,
                        });
                    }
                }
            }
        } else {
            unreachable!()
        }
        self.finish(result)
    }
}

impl<H: crypto::digest::Hmac> HmacClient for Hkdf<H> {
    fn read_key(&self, key: &mut [u8]) -> Result<usize, ErrorCode> {
        if let State::Active { stage, .. } = self.state.get() {
            match stage {
                Stage::Extract => self.read_salt(key),
                Stage::Expand { .. } => self.read_prk(key),
            }
        } else {
            unreachable!()
        }
    }
}

impl<H: crypto::digest::Hmac> SyscallDriver for Hkdf<H> {
    fn command(
        &self,
        command_num: usize,
        data1: usize,
        _data2: usize,
        processid: ProcessId,
    ) -> CommandReturn {
        match command_num {
            0 => CommandReturn::success(),
            1 => match self.start_operation(processid, data1) {
                Ok(()) => CommandReturn::success(),
                Err(e) => CommandReturn::failure(e),
            },
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }
}
