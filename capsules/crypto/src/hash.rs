// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! Hash Userspace Driver

use core::cell::Cell;

use capsules_core::driver;
use capsules_core::driver_mutex::{
    DriverMutex, DriverMutexAny, DriverMutexClient, DriverMutexHandle, DriverMutexRef,
};
use kernel::errorcode::into_statuscode;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, GrantKernelData, UpcallCount};
use kernel::hil::crypto;
use kernel::hil::crypto::digest::{Client, Mode};
use kernel::processbuffer::{ReadableProcessBuffer, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::{MapCell, OptionalCell};
use kernel::{ErrorCode, ProcessId};

/// Syscall driver number.
pub const DRIVER_NUM: usize = driver::NUM::Hash as usize;

/// Upcalls for SHA operations completing.
mod upcall {
    pub const DONE: usize = 0;
    pub const COUNT: u8 = 1;
}

/// Ids for read-only allow buffers
mod ro_allow {
    pub const INPUT: usize = 0;
    /// The number of allow buffers the kernel stores for this grant
    pub const COUNT: u8 = 1;
}

/// Ids for read-write allow buffers
mod rw_allow {
    pub const OUTPUT: usize = 0;
    /// The number of allow buffers the kernel stores for this grant
    pub const COUNT: u8 = 1;
}

#[derive(Clone, Copy)]
enum State {
    Idle,
    Waiting { processid: ProcessId, mode: Mode },
    Active { processid: ProcessId },
}

fn parse_mode(value: usize) -> Result<Mode, ErrorCode> {
    match value {
        0 => Ok(Mode::Md5),
        1 => Ok(Mode::Sha1),
        2 => Ok(Mode::Sha224),
        3 => Ok(Mode::Sha256),
        4 => Ok(Mode::Sha384),
        5 => Ok(Mode::Sha512),
        6 => Ok(Mode::Sha512_224),
        7 => Ok(Mode::Sha512_256),
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

pub struct Hash<H: crypto::digest::Digest + 'static> {
    /// Underlying hasher to use for the SHA operations.
    hash_mutex: &'static DriverMutex<H>,
    hash_handle: OptionalCell<DriverMutexHandle>,
    hash: MapCell<DriverMutexRef<H>>,
    /// Virtualized capsule that supports a single operation per app.
    apps: Grant<
        (),
        UpcallCount<{ upcall::COUNT }>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
    state: Cell<State>,
    input_len: Cell<usize>,
    output_len: Cell<usize>,
    input_offset: Cell<usize>,
    // don't know if I need this
    output_offset: Cell<usize>,
}

impl<H: crypto::digest::Digest> Hash<H> {
    pub fn new(
        hash_mutex: &'static DriverMutex<H>,
        apps: Grant<
            (),
            UpcallCount<{ upcall::COUNT }>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
    ) -> Hash<H> {
        Hash {
            hash_mutex,
            hash_handle: OptionalCell::empty(),
            hash: MapCell::empty(),
            apps,
            state: Cell::new(State::Idle),
            input_len: Cell::new(0),
            output_len: Cell::new(0),
            input_offset: Cell::new(0),
            output_offset: Cell::new(0),
        }
    }

    pub fn register(&'static self) -> Result<(), ErrorCode> {
        if self.hash_handle.is_some() {
            return Err(ErrorCode::ALREADY);
        }

        let hash_handle = self.hash_mutex.add_client(self).ok_or(ErrorCode::NOMEM)?;
        self.hash_handle.set(hash_handle);
        Ok(())
    }

    fn active_processid(&self) -> Result<ProcessId, ErrorCode> {
        match self.state.get() {
            State::Active { processid, .. } => Ok(processid),
            State::Idle | State::Waiting { .. } => Err(ErrorCode::RESERVE),
        }
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

    fn read_input(&self, destination: &mut [u8]) -> Result<usize, ErrorCode> {
        let offset = self.input_offset.get();
        let read = self.read_at(ro_allow::INPUT, offset, destination)?;
        self.input_offset.set(offset + read);
        Ok(read)
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

    fn write_output(&self, source: &[u8]) -> Result<(), ErrorCode> {
        let offset = self.output_offset.get();
        self.write_at(rw_allow::OUTPUT, offset, source)?;
        self.output_offset.set(offset + source.len());
        Ok(())
    }

    fn start_operation(&self, processid: ProcessId, mode_value: usize) -> Result<(), ErrorCode> {
        if !matches!(self.state.get(), State::Idle) {
            return Err(ErrorCode::BUSY);
        }
        if self.hash_handle.is_none() {
            return Err(ErrorCode::OFF);
        }

        let mode = parse_mode(mode_value)?;
        let (input_len, output_len) = self.apps.enter(
            processid,
            |_, kernel_data| -> Result<(usize, usize), ErrorCode> {
                if readwrite_buffer_len(kernel_data, rw_allow::OUTPUT)? != mode.get_digest_len() {
                    return Err(ErrorCode::INVAL);
                }
                let input_len = readonly_buffer_len(kernel_data, ro_allow::INPUT)?;
                let output_len = readwrite_buffer_len(kernel_data, rw_allow::OUTPUT)?;

                Ok((input_len, output_len))
            },
        )??;

        self.input_len.set(input_len);
        self.output_len.set(output_len);
        self.input_offset.set(0);
        self.output_offset.set(0);
        self.state.set(State::Waiting { processid, mode });

        if let Err(error) = self.hash_handle.map_or(Err(ErrorCode::OFF), |handle| {
            self.hash_mutex.request(handle)
        }) {
            self.state.set(State::Idle);
            return Err(error);
        }
        Ok(())
    }

    fn finish(&self, result: Result<(), ErrorCode>) {
        let state = self.state.replace(State::Idle);
        self.hash.take();

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

impl<H: crypto::digest::Digest> DriverMutexClient for Hash<H> {
    fn ready(&'static self, resource: DriverMutexAny) {
        let (processid, mode) = match self.state.get() {
            State::Waiting { processid, mode } => (processid, mode),
            State::Idle | State::Active { .. } => return,
        };
        self.state.set(State::Active { processid });

        let result = match resource.downcast::<H>() {
            Ok(hash) => {
                hash.set_client(self);
                self.hash.put(hash);
                self.hash.map_or(Err(ErrorCode::FAIL), |hash| {
                    hash.hash(mode, self.input_len.get())
                })
            }
            Err(_) => Err(ErrorCode::INVAL),
        };

        if let Err(error) = result {
            self.finish(Err(error));
        }
    }
}

impl<H: crypto::digest::Digest> Client for Hash<H> {
    fn read_input(&self, input: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_input(input)
    }

    fn write_output(&self, output: &[u8]) -> Result<(), ErrorCode> {
        self.write_output(output)
    }

    fn hash_done(&self, result: Result<(), ErrorCode>) {
        self.finish(result)
    }
}

impl<H: crypto::digest::Digest> SyscallDriver for Hash<H> {
    /// Setup and run a SHA hash.
    ///
    /// We expect userspace to setup buffers for the data, and either the
    /// generated hash or a hash to compare with. These buffers must be
    /// allocated and specified to the kernel with allow calls.
    ///
    /// We expect userspace not to change the value while running. If userspace
    /// changes the value we have no guarantee of what is passed to the
    /// hardware. This isn't a security issue, it will just provide the requesting
    /// app with invalid data.
    ///
    /// The driver will take care of clearing data from the underlying
    /// implementation by calling the `clear_data()` function when the
    /// `hash_complete()` callback is called or if an error is encountered.
    ///
    /// ### `command_num`
    ///
    /// - `0`: driver check
    /// - `1`: hash
    fn command(
        &self,
        command_num: usize,
        data1: usize,
        _data2: usize,
        processid: ProcessId,
    ) -> CommandReturn {
        match command_num {
            // check if present
            0 => CommandReturn::success(),

            // start hash operation
            1 => match self.start_operation(processid, data1) {
                Ok(()) => CommandReturn::success(),
                Err(e) => CommandReturn::failure(e),
            },

            // default
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }
}
