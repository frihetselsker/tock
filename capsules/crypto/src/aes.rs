// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! Syscall driver for mode-specific AES-128 cipher HILs.
//!
//! # System call interface
//!
//! ## `subscribe_num`
//!
//! - `0`: operation completion. Callback arguments are `(status, output_len, 0)`.
//!
//! ## Read-only allow buffers
//!
//! - `0`: 16-byte AES-128 key
//! - `1`: IV (16 bytes for CBC, 12 bytes for GCM)
//! - `2`: nonce (CCM or the high-order portion of a CTR counter block)
//! - `3`: low-order CTR counter value
//! - `4`: plaintext or ciphertext payload
//! - `5`: associated data
//! - `6`: authentication tag for CCM or GCM decryption
//!
//! ## Read-write allow buffers
//!
//! - `0`: ciphertext or plaintext payload
//! - `1`: chaining IV returned by CBC
//! - `2`: authentication tag returned by CCM or GCM encryption
//!
//! ## Commands
//!
//! - `0`: existence check
//! - `1`: perform an AES-128 operation. `data1` is the mode and `data2` is the operation.
//!
//! Mode values are `0 = CBC`, `1 = CCM`, `2 = CTR`, `3 = ECB`, and `4 = GCM`.
//! Operation values are `0 = encrypt` and `1 = decrypt`. Payload, associated-data, and tag
//! lengths are inferred from the corresponding allow buffers.

use capsules_core::driver;
use capsules_core::driver_mutex::{
    DriverMutex, DriverMutexAny, DriverMutexClient, DriverMutexHandle, DriverMutexRef,
};
use core::cell::Cell;
use kernel::errorcode::into_statuscode;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, GrantKernelData, UpcallCount};
use kernel::hil::crypto::cipher::{
    Aes128, Cbc, CbcClient, Ccm, CcmClient, CcmTagLength, Ctr, CtrClient, Ecb, EcbClient, Gcm,
    GcmClient, GcmTagLength, Operation,
};
use kernel::processbuffer::{ReadableProcessBuffer, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::{MapCell, OptionalCell};
use kernel::{ErrorCode, ProcessId};

/// Syscall driver number.
pub const DRIVER_NUM: usize = driver::NUM::Aes as usize;

const AES128_KEY_SIZE: usize = 16;
const BLOCK_SIZE: usize = 16;
const GCM_IV_SIZE: usize = 12;

mod upcall {
    pub const DONE: usize = 0;
    pub const COUNT: u8 = 1;
}

mod ro_allow {
    pub const KEY: usize = 0;
    pub const IV: usize = 1;
    pub const NONCE: usize = 2;
    pub const COUNTER: usize = 3;
    pub const INPUT: usize = 4;
    pub const ASSOCIATED_DATA: usize = 5;
    pub const TAG: usize = 6;
    pub const COUNT: u8 = 7;
}

mod rw_allow {
    pub const OUTPUT: usize = 0;
    pub const IV: usize = 1;
    pub const TAG: usize = 2;
    pub const COUNT: u8 = 3;
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Cbc,
    Ccm,
    Ctr,
    Ecb,
    Gcm,
}

#[derive(Clone, Copy)]
enum State {
    Idle,
    Waiting { processid: ProcessId, mode: Mode },
    Active { processid: ProcessId },
}

fn parse_mode(value: usize) -> Result<Mode, ErrorCode> {
    match value {
        0 => Ok(Mode::Cbc),
        1 => Ok(Mode::Ccm),
        2 => Ok(Mode::Ctr),
        3 => Ok(Mode::Ecb),
        4 => Ok(Mode::Gcm),
        _ => Err(ErrorCode::INVAL),
    }
}

fn parse_operation(value: usize) -> Result<Operation, ErrorCode> {
    match value {
        0 => Ok(Operation::Encrypt),
        1 => Ok(Operation::Decrypt),
        _ => Err(ErrorCode::INVAL),
    }
}

fn parse_ccm_tag_length(value: usize) -> Result<CcmTagLength, ErrorCode> {
    match value {
        4 => Ok(CcmTagLength::Tag32),
        6 => Ok(CcmTagLength::Tag48),
        8 => Ok(CcmTagLength::Tag64),
        10 => Ok(CcmTagLength::Tag80),
        12 => Ok(CcmTagLength::Tag96),
        14 => Ok(CcmTagLength::Tag112),
        16 => Ok(CcmTagLength::Tag128),
        _ => Err(ErrorCode::INVAL),
    }
}

fn parse_gcm_tag_length(value: usize) -> Result<GcmTagLength, ErrorCode> {
    match value {
        4 => Ok(GcmTagLength::Tag32),
        8 => Ok(GcmTagLength::Tag64),
        12 => Ok(GcmTagLength::Tag96),
        13 => Ok(GcmTagLength::Tag104),
        14 => Ok(GcmTagLength::Tag112),
        15 => Ok(GcmTagLength::Tag120),
        16 => Ok(GcmTagLength::Tag128),
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

/// Userspace AES-128 driver over independently mutexed cipher modes.
pub struct Aes128CipherDriver<
    CBC: Cbc<Aes128> + 'static,
    CCM: Ccm<Aes128> + 'static,
    CTR: Ctr<Aes128> + 'static,
    ECB: Ecb<Aes128> + 'static,
    GCM: Gcm<Aes128> + 'static,
> {
    cbc_mutex: &'static DriverMutex<CBC>,
    ccm_mutex: &'static DriverMutex<CCM>,
    ctr_mutex: &'static DriverMutex<CTR>,
    ecb_mutex: &'static DriverMutex<ECB>,
    gcm_mutex: &'static DriverMutex<GCM>,
    cbc_handle: OptionalCell<DriverMutexHandle>,
    ccm_handle: OptionalCell<DriverMutexHandle>,
    ctr_handle: OptionalCell<DriverMutexHandle>,
    ecb_handle: OptionalCell<DriverMutexHandle>,
    gcm_handle: OptionalCell<DriverMutexHandle>,
    cbc: MapCell<DriverMutexRef<CBC>>,
    ccm: MapCell<DriverMutexRef<CCM>>,
    ctr: MapCell<DriverMutexRef<CTR>>,
    ecb: MapCell<DriverMutexRef<ECB>>,
    gcm: MapCell<DriverMutexRef<GCM>>,
    apps: Grant<
        (),
        UpcallCount<{ upcall::COUNT }>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
    state: Cell<State>,
    operation: Cell<Operation>,
    input_len: Cell<usize>,
    associated_data_len: Cell<usize>,
    tag_len: Cell<usize>,
    input_offset: Cell<usize>,
    associated_data_offset: Cell<usize>,
    output_offset: Cell<usize>,
    ccm_output_offset: Cell<usize>,
}

impl<
    CBC: Cbc<Aes128> + 'static,
    CCM: Ccm<Aes128> + 'static,
    CTR: Ctr<Aes128> + 'static,
    ECB: Ecb<Aes128> + 'static,
    GCM: Gcm<Aes128> + 'static,
> Aes128CipherDriver<CBC, CCM, CTR, ECB, GCM>
{
    /// Create an AES-128 syscall driver over mode-specific mutex resources.
    pub fn new(
        cbc_mutex: &'static DriverMutex<CBC>,
        ccm_mutex: &'static DriverMutex<CCM>,
        ctr_mutex: &'static DriverMutex<CTR>,
        ecb_mutex: &'static DriverMutex<ECB>,
        gcm_mutex: &'static DriverMutex<GCM>,
        apps: Grant<
            (),
            UpcallCount<{ upcall::COUNT }>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
    ) -> Self {
        Self {
            cbc_mutex,
            ccm_mutex,
            ctr_mutex,
            ecb_mutex,
            gcm_mutex,
            cbc_handle: OptionalCell::empty(),
            ccm_handle: OptionalCell::empty(),
            ctr_handle: OptionalCell::empty(),
            ecb_handle: OptionalCell::empty(),
            gcm_handle: OptionalCell::empty(),
            cbc: MapCell::empty(),
            ccm: MapCell::empty(),
            ctr: MapCell::empty(),
            ecb: MapCell::empty(),
            gcm: MapCell::empty(),
            apps,
            state: Cell::new(State::Idle),
            operation: Cell::new(Operation::Encrypt),
            input_len: Cell::new(0),
            associated_data_len: Cell::new(0),
            tag_len: Cell::new(0),
            input_offset: Cell::new(0),
            associated_data_offset: Cell::new(0),
            output_offset: Cell::new(0),
            ccm_output_offset: Cell::new(0),
        }
    }

    /// Register this driver as a client of all five mode mutexes.
    pub fn register(&'static self) -> Result<(), ErrorCode> {
        if self.cbc_handle.is_some()
            || self.ccm_handle.is_some()
            || self.ctr_handle.is_some()
            || self.ecb_handle.is_some()
            || self.gcm_handle.is_some()
        {
            return Err(ErrorCode::ALREADY);
        }

        let cbc_handle = self.cbc_mutex.add_client(self).ok_or(ErrorCode::NOMEM)?;
        let ccm_handle = self.ccm_mutex.add_client(self).ok_or(ErrorCode::NOMEM)?;
        let ctr_handle = self.ctr_mutex.add_client(self).ok_or(ErrorCode::NOMEM)?;
        let ecb_handle = self.ecb_mutex.add_client(self).ok_or(ErrorCode::NOMEM)?;
        let gcm_handle = self.gcm_mutex.add_client(self).ok_or(ErrorCode::NOMEM)?;
        self.cbc_handle.set(cbc_handle);
        self.ccm_handle.set(ccm_handle);
        self.ctr_handle.set(ctr_handle);
        self.ecb_handle.set(ecb_handle);
        self.gcm_handle.set(gcm_handle);
        Ok(())
    }

    fn active_processid(&self) -> Result<ProcessId, ErrorCode> {
        match self.state.get() {
            State::Active { processid, .. } => Ok(processid),
            State::Idle | State::Waiting { .. } => Err(ErrorCode::RESERVE),
        }
    }

    fn read_exact(&self, allow_number: usize, destination: &mut [u8]) -> Result<(), ErrorCode> {
        let processid = self.active_processid()?;
        self.apps
            .enter(processid, |_, kernel_data| {
                kernel_data
                    .get_readonly_processbuffer(allow_number)
                    .and_then(|buffer| {
                        buffer.enter(|source| {
                            if source.len() != destination.len() {
                                return Err(ErrorCode::SIZE);
                            }
                            source.copy_to_slice(destination);
                            Ok(())
                        })
                    })
                    .unwrap_or(Err(ErrorCode::RESERVE))
            })
            .unwrap_or_else(|error| Err(error.into()))
    }

    fn read_buffer(&self, allow_number: usize, destination: &mut [u8]) -> Result<usize, ErrorCode> {
        let processid = self.active_processid()?;
        self.apps
            .enter(processid, |_, kernel_data| {
                kernel_data
                    .get_readonly_processbuffer(allow_number)
                    .and_then(|buffer| {
                        buffer.enter(|source| {
                            if source.len() > destination.len() {
                                return Err(ErrorCode::SIZE);
                            }
                            source.copy_to_slice(&mut destination[..source.len()]);
                            Ok(source.len())
                        })
                    })
                    .unwrap_or(Err(ErrorCode::RESERVE))
            })
            .unwrap_or_else(|error| Err(error.into()))
    }

    fn read_at(
        &self,
        allow_number: usize,
        offset: usize,
        destination: &mut [u8],
    ) -> Result<usize, ErrorCode> {
        let processid = self.active_processid()?;
        self.apps
            .enter(processid, |_, kernel_data| {
                kernel_data
                    .get_readonly_processbuffer(allow_number)
                    .and_then(|buffer| {
                        buffer.enter(|source| {
                            if offset >= source.len() || destination.is_empty() {
                                return Err(ErrorCode::SIZE);
                            }
                            let read_len = destination.len().min(source.len() - offset);
                            source[offset..offset + read_len]
                                .copy_to_slice(&mut destination[..read_len]);
                            Ok(read_len)
                        })
                    })
                    .unwrap_or(Err(ErrorCode::RESERVE))
            })
            .unwrap_or_else(|error| Err(error.into()))
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

    fn read_input(&self, destination: &mut [u8]) -> Result<usize, ErrorCode> {
        let offset = self.input_offset.get();
        let read = self.read_at(ro_allow::INPUT, offset, destination)?;
        self.input_offset.set(offset + read);
        Ok(read)
    }

    fn read_associated_data(&self, destination: &mut [u8]) -> Result<usize, ErrorCode> {
        let offset = self.associated_data_offset.get();
        let read = self.read_at(ro_allow::ASSOCIATED_DATA, offset, destination)?;
        self.associated_data_offset.set(offset + read);
        Ok(read)
    }

    fn read_ccm_input(&self, destination: &mut [u8]) -> Result<usize, ErrorCode> {
        if self.operation.get() == Operation::Encrypt {
            return self.read_input(destination);
        }

        let payload_len = self.input_len.get();
        let total_len = payload_len
            .checked_add(self.tag_len.get())
            .ok_or(ErrorCode::SIZE)?;
        let mut stream_offset = self.input_offset.get();
        let mut written = 0;
        while written < destination.len() && stream_offset < total_len {
            let read = if stream_offset < payload_len {
                let available = payload_len - stream_offset;
                let read_len = available.min(destination.len() - written);
                self.read_at(
                    ro_allow::INPUT,
                    stream_offset,
                    &mut destination[written..written + read_len],
                )?
            } else {
                let tag_offset = stream_offset - payload_len;
                self.read_at(ro_allow::TAG, tag_offset, &mut destination[written..])?
            };
            written += read;
            stream_offset += read;
        }
        if written == 0 {
            return Err(ErrorCode::SIZE);
        }
        self.input_offset.set(stream_offset);
        Ok(written)
    }

    fn write_output(&self, source: &[u8]) -> Result<(), ErrorCode> {
        let offset = self.output_offset.get();
        self.write_at(rw_allow::OUTPUT, offset, source)?;
        self.output_offset.set(offset + source.len());
        Ok(())
    }

    fn write_ccm_output(&self, source: &[u8]) -> Result<(), ErrorCode> {
        if self.operation.get() == Operation::Decrypt {
            return self.write_output(source);
        }

        let payload_len = self.input_len.get();
        let mut stream_offset = self.ccm_output_offset.get();
        let mut source_offset = 0;
        while source_offset < source.len() {
            if stream_offset < payload_len {
                let write_len = (payload_len - stream_offset).min(source.len() - source_offset);
                self.write_at(
                    rw_allow::OUTPUT,
                    stream_offset,
                    &source[source_offset..source_offset + write_len],
                )?;
                self.output_offset.set(self.output_offset.get() + write_len);
                stream_offset += write_len;
                source_offset += write_len;
            } else {
                let tag_offset = stream_offset - payload_len;
                self.write_at(rw_allow::TAG, tag_offset, &source[source_offset..])?;
                stream_offset += source.len() - source_offset;
                source_offset = source.len();
            }
        }
        self.ccm_output_offset.set(stream_offset);
        Ok(())
    }

    fn start_operation(
        &self,
        processid: ProcessId,
        mode_value: usize,
        operation_value: usize,
    ) -> Result<(), ErrorCode> {
        if !matches!(self.state.get(), State::Idle) {
            return Err(ErrorCode::BUSY);
        }
        if self.cbc_handle.is_none()
            || self.ccm_handle.is_none()
            || self.ctr_handle.is_none()
            || self.ecb_handle.is_none()
            || self.gcm_handle.is_none()
        {
            return Err(ErrorCode::OFF);
        }

        let mode = parse_mode(mode_value)?;
        let operation = parse_operation(operation_value)?;
        let (input_len, associated_data_len, tag_len) = self.apps.enter(
            processid,
            |_, kernel_data| -> Result<(usize, usize, usize), ErrorCode> {
                if readonly_buffer_len(kernel_data, ro_allow::KEY)? != AES128_KEY_SIZE {
                    return Err(ErrorCode::INVAL);
                }
                let input_len = readonly_buffer_len(kernel_data, ro_allow::INPUT)?;
                let output_len = readwrite_buffer_len(kernel_data, rw_allow::OUTPUT)?;
                if output_len < input_len {
                    return Err(ErrorCode::SIZE);
                }

                let associated_data_len = match mode {
                    Mode::Ccm | Mode::Gcm => {
                        readonly_buffer_len(kernel_data, ro_allow::ASSOCIATED_DATA)?
                    }
                    Mode::Cbc | Mode::Ctr | Mode::Ecb => 0,
                };
                let tag_len = match (mode, operation) {
                    (Mode::Ccm | Mode::Gcm, Operation::Encrypt) => {
                        readwrite_buffer_len(kernel_data, rw_allow::TAG)?
                    }
                    (Mode::Ccm | Mode::Gcm, Operation::Decrypt) => {
                        readonly_buffer_len(kernel_data, ro_allow::TAG)?
                    }
                    _ => 0,
                };

                match mode {
                    Mode::Cbc => {
                        if readonly_buffer_len(kernel_data, ro_allow::IV)? != BLOCK_SIZE
                            || readwrite_buffer_len(kernel_data, rw_allow::IV)? < BLOCK_SIZE
                        {
                            return Err(ErrorCode::INVAL);
                        }
                    }
                    Mode::Ccm => {
                        if !(7..=13).contains(&readonly_buffer_len(kernel_data, ro_allow::NONCE)?) {
                            return Err(ErrorCode::INVAL);
                        }
                        parse_ccm_tag_length(tag_len)?;
                    }
                    Mode::Ctr => {
                        let nonce_len = readonly_buffer_len(kernel_data, ro_allow::NONCE)?;
                        let counter_len = readonly_buffer_len(kernel_data, ro_allow::COUNTER)?;
                        if counter_len == 0 || nonce_len + counter_len != BLOCK_SIZE {
                            return Err(ErrorCode::INVAL);
                        }
                    }
                    Mode::Ecb => {}
                    Mode::Gcm => {
                        if readonly_buffer_len(kernel_data, ro_allow::IV)? != GCM_IV_SIZE {
                            return Err(ErrorCode::INVAL);
                        }
                        parse_gcm_tag_length(tag_len)?;
                    }
                }
                Ok((input_len, associated_data_len, tag_len))
            },
        )??;

        self.operation.set(operation);
        self.input_len.set(input_len);
        self.associated_data_len.set(associated_data_len);
        self.tag_len.set(tag_len);
        self.input_offset.set(0);
        self.associated_data_offset.set(0);
        self.output_offset.set(0);
        self.ccm_output_offset.set(0);
        self.state.set(State::Waiting { processid, mode });

        let result = match mode {
            Mode::Cbc => self
                .cbc_handle
                .map_or(Err(ErrorCode::OFF), |handle| self.cbc_mutex.request(handle)),
            Mode::Ccm => self
                .ccm_handle
                .map_or(Err(ErrorCode::OFF), |handle| self.ccm_mutex.request(handle)),
            Mode::Ctr => self
                .ctr_handle
                .map_or(Err(ErrorCode::OFF), |handle| self.ctr_mutex.request(handle)),
            Mode::Ecb => self
                .ecb_handle
                .map_or(Err(ErrorCode::OFF), |handle| self.ecb_mutex.request(handle)),
            Mode::Gcm => self
                .gcm_handle
                .map_or(Err(ErrorCode::OFF), |handle| self.gcm_mutex.request(handle)),
        };
        if let Err(error) = result {
            self.state.set(State::Idle);
            return Err(error);
        }
        Ok(())
    }

    fn finish(&self, result: Result<(), ErrorCode>) {
        let state = self.state.replace(State::Idle);
        self.cbc.take();
        self.ccm.take();
        self.ctr.take();
        self.ecb.take();
        self.gcm.take();

        let processid = match state {
            State::Waiting { processid, .. } | State::Active { processid, .. } => processid,
            State::Idle => return,
        };
        let output_len = self.output_offset.get();
        let _ = self.apps.enter(processid, |_, kernel_data| {
            let _ =
                kernel_data.schedule_upcall(upcall::DONE, (into_statuscode(result), output_len, 0));
        });
    }
}

impl<
    CBC: Cbc<Aes128> + 'static,
    CCM: Ccm<Aes128> + 'static,
    CTR: Ctr<Aes128> + 'static,
    ECB: Ecb<Aes128> + 'static,
    GCM: Gcm<Aes128> + 'static,
> DriverMutexClient for Aes128CipherDriver<CBC, CCM, CTR, ECB, GCM>
{
    fn ready(&'static self, resource: DriverMutexAny) {
        let (processid, mode) = match self.state.get() {
            State::Waiting { processid, mode } => (processid, mode),
            State::Idle | State::Active { .. } => return,
        };
        self.state.set(State::Active { processid });

        let result = match mode {
            Mode::Cbc => match resource.downcast::<CBC>() {
                Ok(cbc) => {
                    cbc.set_client(self);
                    self.cbc.put(cbc);
                    self.cbc.map_or(Err(ErrorCode::FAIL), |cbc| {
                        cbc.crypt(self.input_len.get(), self.operation.get())
                    })
                }
                Err(_) => Err(ErrorCode::INVAL),
            },
            Mode::Ccm => match resource.downcast::<CCM>() {
                Ok(ccm) => {
                    ccm.set_client(self);
                    self.ccm.put(ccm);
                    self.ccm.map_or(Err(ErrorCode::FAIL), |ccm| {
                        ccm.crypt(
                            self.input_len.get(),
                            self.associated_data_len.get(),
                            parse_ccm_tag_length(self.tag_len.get())?,
                            self.operation.get(),
                        )
                    })
                }
                Err(_) => Err(ErrorCode::INVAL),
            },
            Mode::Ctr => match resource.downcast::<CTR>() {
                Ok(ctr) => {
                    ctr.set_client(self);
                    self.ctr.put(ctr);
                    self.ctr.map_or(Err(ErrorCode::FAIL), |ctr| {
                        ctr.crypt(self.input_len.get(), self.operation.get())
                    })
                }
                Err(_) => Err(ErrorCode::INVAL),
            },
            Mode::Ecb => match resource.downcast::<ECB>() {
                Ok(ecb) => {
                    ecb.set_client(self);
                    self.ecb.put(ecb);
                    self.ecb.map_or(Err(ErrorCode::FAIL), |ecb| {
                        ecb.crypt(self.input_len.get(), self.operation.get())
                    })
                }
                Err(_) => Err(ErrorCode::INVAL),
            },
            Mode::Gcm => match resource.downcast::<GCM>() {
                Ok(gcm) => {
                    gcm.set_client(self);
                    self.gcm.put(gcm);
                    self.gcm.map_or(Err(ErrorCode::FAIL), |gcm| {
                        gcm.crypt(
                            self.input_len.get(),
                            self.associated_data_len.get(),
                            parse_gcm_tag_length(self.tag_len.get())?,
                            self.operation.get(),
                        )
                    })
                }
                Err(_) => Err(ErrorCode::INVAL),
            },
        };
        if let Err(error) = result {
            self.finish(Err(error));
        }
    }
}

impl<
    CBC: Cbc<Aes128> + 'static,
    CCM: Ccm<Aes128> + 'static,
    CTR: Ctr<Aes128> + 'static,
    ECB: Ecb<Aes128> + 'static,
    GCM: Gcm<Aes128> + 'static,
> CbcClient<Aes128> for Aes128CipherDriver<CBC, CCM, CTR, ECB, GCM>
{
    fn read_key(&self, key: &mut [u8]) -> Result<(), ErrorCode> {
        self.read_exact(ro_allow::KEY, key)
    }

    fn read_iv(&self, iv: &mut [u8]) -> Result<(), ErrorCode> {
        self.read_exact(ro_allow::IV, iv)
    }

    fn read_input(&self, input: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_input(input)
    }

    fn write_output(&self, output: &[u8]) -> Result<(), ErrorCode> {
        self.write_output(output)
    }

    fn write_iv(&self, iv: &[u8]) -> Result<(), ErrorCode> {
        self.write_at(rw_allow::IV, 0, iv)
    }

    fn crypt_done(&self, result: Result<(), ErrorCode>) {
        self.finish(result);
    }
}

impl<
    CBC: Cbc<Aes128> + 'static,
    CCM: Ccm<Aes128> + 'static,
    CTR: Ctr<Aes128> + 'static,
    ECB: Ecb<Aes128> + 'static,
    GCM: Gcm<Aes128> + 'static,
> CcmClient<Aes128> for Aes128CipherDriver<CBC, CCM, CTR, ECB, GCM>
{
    fn read_key(&self, key: &mut [u8]) -> Result<(), ErrorCode> {
        self.read_exact(ro_allow::KEY, key)
    }

    fn read_nonce(&self, nonce: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_buffer(ro_allow::NONCE, nonce)
    }

    fn read_associated_data(&self, associated_data: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_associated_data(associated_data)
    }

    fn read_input(&self, input: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_ccm_input(input)
    }

    fn write_output(&self, output: &[u8]) -> Result<(), ErrorCode> {
        self.write_ccm_output(output)
    }

    fn crypt_done(&self, result: Result<(), ErrorCode>) {
        self.finish(result);
    }
}

impl<
    CBC: Cbc<Aes128> + 'static,
    CCM: Ccm<Aes128> + 'static,
    CTR: Ctr<Aes128> + 'static,
    ECB: Ecb<Aes128> + 'static,
    GCM: Gcm<Aes128> + 'static,
> CtrClient<Aes128> for Aes128CipherDriver<CBC, CCM, CTR, ECB, GCM>
{
    fn read_key(&self, key: &mut [u8]) -> Result<(), ErrorCode> {
        self.read_exact(ro_allow::KEY, key)
    }

    fn read_nonce(&self, nonce: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_buffer(ro_allow::NONCE, nonce)
    }

    fn read_counter(&self, counter: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_buffer(ro_allow::COUNTER, counter)
    }

    fn read_input(&self, input: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_input(input)
    }

    fn write_output(&self, output: &[u8]) -> Result<(), ErrorCode> {
        self.write_output(output)
    }

    fn crypt_done(&self, result: Result<(), ErrorCode>) {
        self.finish(result);
    }
}

impl<
    CBC: Cbc<Aes128> + 'static,
    CCM: Ccm<Aes128> + 'static,
    CTR: Ctr<Aes128> + 'static,
    ECB: Ecb<Aes128> + 'static,
    GCM: Gcm<Aes128> + 'static,
> EcbClient<Aes128> for Aes128CipherDriver<CBC, CCM, CTR, ECB, GCM>
{
    fn read_key(&self, key: &mut [u8]) -> Result<(), ErrorCode> {
        self.read_exact(ro_allow::KEY, key)
    }

    fn read_input(&self, input: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_input(input)
    }

    fn write_output(&self, output: &[u8]) -> Result<(), ErrorCode> {
        self.write_output(output)
    }

    fn crypt_done(&self, result: Result<(), ErrorCode>) {
        self.finish(result);
    }
}

impl<
    CBC: Cbc<Aes128> + 'static,
    CCM: Ccm<Aes128> + 'static,
    CTR: Ctr<Aes128> + 'static,
    ECB: Ecb<Aes128> + 'static,
    GCM: Gcm<Aes128> + 'static,
> GcmClient<Aes128> for Aes128CipherDriver<CBC, CCM, CTR, ECB, GCM>
{
    fn read_key(&self, key: &mut [u8]) -> Result<(), ErrorCode> {
        self.read_exact(ro_allow::KEY, key)
    }

    fn read_iv(&self, iv: &mut [u8]) -> Result<(), ErrorCode> {
        self.read_exact(ro_allow::IV, iv)
    }

    fn read_associated_data(&self, associated_data: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_associated_data(associated_data)
    }

    fn read_input(&self, input: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_input(input)
    }

    fn read_tag(&self, tag: &mut [u8]) -> Result<(), ErrorCode> {
        self.read_exact(ro_allow::TAG, tag)
    }

    fn write_output(&self, output: &[u8]) -> Result<(), ErrorCode> {
        self.write_output(output)
    }

    fn write_tag(&self, tag: &[u8]) -> Result<(), ErrorCode> {
        self.write_at(rw_allow::TAG, 0, tag)
    }

    fn crypt_done(&self, result: Result<(), ErrorCode>) {
        self.finish(result);
    }
}

impl<
    CBC: Cbc<Aes128> + 'static,
    CCM: Ccm<Aes128> + 'static,
    CTR: Ctr<Aes128> + 'static,
    ECB: Ecb<Aes128> + 'static,
    GCM: Gcm<Aes128> + 'static,
> SyscallDriver for Aes128CipherDriver<CBC, CCM, CTR, ECB, GCM>
{
    fn command(
        &self,
        command_num: usize,
        data1: usize,
        data2: usize,
        processid: ProcessId,
    ) -> CommandReturn {
        match command_num {
            0 => CommandReturn::success(),
            1 => match self.start_operation(processid, data1, data2) {
                Ok(()) => CommandReturn::success(),
                Err(error) => CommandReturn::failure(error),
            },
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }
}
