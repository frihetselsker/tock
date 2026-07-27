// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! Syscall driver for AES operations through the crypto AES HIL.
//!
//! # System call interface
//!
//! ## `subscribe_num`
//!
//! - `0`: operation completion. Callback arguments are `(status, output_len, 0)`.
//!
//! ## Read-only allow buffers
//!
//! - `0`: key
//! - `1`: IV
//! - `2`: nonce
//! - `3`: counter
//! - `4`: input
//! - `5`: associated data
//! - `6`: tag input for authenticated decryption
//!
//! ## Read-write allow buffers
//!
//! - `0`: output
//! - `1`: IV output for modes that return a chaining IV
//! - `2`: tag output for authenticated encryption
//!
//! ## Commands
//!
//! - `0`: existence check
//! - `1`: perform AES operation. `data1` is the mode and `data2` is the operation.
//!
//! Mode values for command 1 `data1` are:
//!
//! ```text
//! 0 = CBC, 1 = CCM, 2 = CTR, 3 = ECB, 4 = GCM
//! ```
//!
//! Operation values for command 1 `data2` are:
//!
//! ```text
//! 0 = encrypt, 1 = decrypt
//! ```
//!
//! Length parameters are inferred from the current allow buffers when command 1 is called.

use capsules_core::driver;
use core::cell::Cell;
use kernel::errorcode::into_statuscode;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, GrantKernelData, UpcallCount};
use kernel::hil::crypto::aes::{Aes, AesClient, KeyLength, Mode, Operation, TagLength, BLOCK_SIZE};
use kernel::processbuffer::{ReadableProcessBuffer, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::{ErrorCode, ProcessId};

/// Syscall driver number.
pub const DRIVER_NUM: usize = driver::NUM::Aes as usize;

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

mod mode {
    pub const CBC: usize = 0;
    pub const CCM: usize = 1;
    pub const CTR: usize = 2;
    pub const ECB: usize = 3;
    pub const GCM: usize = 4;
}

mod operation {
    pub const ENCRYPT: usize = 0;
    pub const DECRYPT: usize = 1;
}

/// Tracks whether the driver is idle or serving a process operation.
#[derive(Clone, Copy)]
enum State {
    /// No operation is currently running.
    Idle,

    /// An operation is in progress for one process.
    Active { pid: ProcessId, output_len: usize },
}

/// Return the length of a read-only allow buffer.
fn readonly_buffer_len(kd: &GrantKernelData<'_>, num: usize) -> Result<usize, ErrorCode> {
    kd.get_readonly_processbuffer(num)
        .map(|buffer| buffer.len())
        .map_err(|err| err.into())
}

/// Return the length of a read-write allow buffer.
fn readwrite_buffer_len(kd: &GrantKernelData<'_>, num: usize) -> Result<usize, ErrorCode> {
    kd.get_readwrite_processbuffer(num)
        .map(|buffer| buffer.len())
        .map_err(|err| err.into())
}

/// Decode the userspace mode selector into the AES HIL mode type.
fn parse_mode(mode: usize, ad_len: usize, tag_len: usize) -> Result<Mode, ErrorCode> {
    match mode {
        mode::CBC => Ok(Mode::Cbc),
        mode::CCM => Ok(Mode::Ccm { ad_len }),
        mode::CTR => Ok(Mode::Ctr),
        mode::ECB => Ok(Mode::Ecb),
        mode::GCM => Ok(Mode::Gcm {
            tag_len: parse_tag_length(tag_len)?,
            ad_len,
        }),
        _ => Err(ErrorCode::INVAL),
    }
}

/// Decode the userspace operation selector.
fn parse_operation(operation: usize) -> Result<Operation, ErrorCode> {
    match operation {
        operation::ENCRYPT => Ok(Operation::Encrypt),
        operation::DECRYPT => Ok(Operation::Decrypt),
        _ => Err(ErrorCode::INVAL),
    }
}

/// Convert the userspace key allow length into a HIL key length.
fn parse_key_length(key_len: usize) -> Result<KeyLength, ErrorCode> {
    match key_len {
        16 => Ok(KeyLength::Aes128),
        24 => Ok(KeyLength::Aes192),
        32 => Ok(KeyLength::Aes256),
        _ => Err(ErrorCode::INVAL),
    }
}

/// Convert the userspace GCM tag allow length into a HIL tag length.
fn parse_tag_length(tag_len: usize) -> Result<TagLength, ErrorCode> {
    match tag_len {
        4 => Ok(TagLength::Tag32),
        8 => Ok(TagLength::Tag64),
        12 => Ok(TagLength::Tag96),
        13 => Ok(TagLength::Tag104),
        14 => Ok(TagLength::Tag112),
        15 => Ok(TagLength::Tag120),
        16 => Ok(TagLength::Tag128),
        _ => Err(ErrorCode::INVAL),
    }
}

/// Syscall driver that exposes the AES HIL to userspace.
pub struct AesDriver<'a, A: Aes> {
    aes: &'a A,
    apps: Grant<
        (),
        UpcallCount<{ upcall::COUNT }>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
    state: Cell<State>,
}

impl<'a, A: Aes> AesDriver<'a, A> {
    /// Create a new AES syscall driver over an AES HIL implementation.
    pub fn new(
        aes: &'a A,
        grant: Grant<
            (),
            UpcallCount<{ upcall::COUNT }>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
    ) -> Self {
        Self {
            aes,
            apps: grant,
            state: Cell::new(State::Idle),
        }
    }

    /// Parse the userspace request and begin an AES operation.
    fn start_operation(&self, pid: ProcessId, mode: usize, op: usize) -> Result<(), ErrorCode> {
        match self.state.get() {
            State::Idle => {}
            State::Active { .. } => return Err(ErrorCode::BUSY),
        }

        let op = parse_operation(op)?;

        let (input_len, key_len, mode) = self.apps.enter(
            pid,
            |_, kernel_data| -> Result<(usize, KeyLength, Mode), ErrorCode> {
                let input_len = readonly_buffer_len(kernel_data, ro_allow::INPUT)?;

                let key_len = readonly_buffer_len(kernel_data, ro_allow::KEY)?;
                let key_len = parse_key_length(key_len)?;

                let ad_len = readonly_buffer_len(kernel_data, ro_allow::ASSOCIATED_DATA)?;
                let tag_len = if mode == mode::GCM {
                    match op {
                        Operation::Encrypt => readwrite_buffer_len(kernel_data, rw_allow::TAG)?,
                        Operation::Decrypt => readonly_buffer_len(kernel_data, ro_allow::TAG)?,
                    }
                } else {
                    0
                };

                let mode = parse_mode(mode, ad_len, tag_len)?;

                Ok((input_len, key_len, mode))
            },
        )??;

        self.state.set(State::Active { pid, output_len: 0 });

        let res = self.aes.crypt(input_len, key_len, mode, op);
        if res.is_err() {
            self.state.set(State::Idle);
        }

        res
    }

    /// Return the process that owns the currently active operation.
    fn active_processid(&self) -> Result<ProcessId, ErrorCode> {
        match self.state.get() {
            State::Active { pid: processid, .. } => Ok(processid),
            State::Idle => Err(ErrorCode::RESERVE),
        }
    }

    /// Read exactly the size of the destination buffer from an allow buffer.
    fn read_exact(&self, allow_num: usize, destination: &mut [u8]) -> Result<(), ErrorCode> {
        let processid = self.active_processid()?;

        self.apps
            .enter(processid, |_, kernel_data| {
                kernel_data
                    .get_readonly_processbuffer(allow_num)
                    .and_then(|buffer| {
                        buffer.enter(|source| {
                            if source.len() < destination.len() {
                                Err(ErrorCode::SIZE)
                            } else {
                                source[..destination.len()].copy_to_slice(destination);
                                Ok(())
                            }
                        })
                    })
                    .unwrap_or(Err(ErrorCode::RESERVE))
            })
            .unwrap_or_else(|err| Err(err.into()))
    }

    /// Read a variable-length allow buffer into a HIL-provided destination.
    fn read_len(&self, allow_num: usize, destination: &mut [u8]) -> Result<usize, ErrorCode> {
        let processid = self.active_processid()?;

        self.apps
            .enter(processid, |_, kernel_data| {
                kernel_data
                    .get_readonly_processbuffer(allow_num)
                    .and_then(|buffer| {
                        buffer.enter(|source| {
                            let len = source.len();

                            if destination.len() < len {
                                Err(ErrorCode::SIZE)
                            } else {
                                source[..len].copy_to_slice(&mut destination[..len]);
                                Ok(len)
                            }
                        })
                    })
                    .unwrap_or(Err(ErrorCode::RESERVE))
            })
            .unwrap_or_else(|err| Err(err.into()))
    }

    /// Record the number of bytes written by the HIL for completion reporting.
    fn set_active_output_len(&self, output_len: usize) -> Result<(), ErrorCode> {
        match self.state.get() {
            State::Active { pid: processid, .. } => {
                self.state.set(State::Active {
                    pid: processid,
                    output_len,
                });
                Ok(())
            }
            State::Idle => Err(ErrorCode::RESERVE),
        }
    }

    /// Write HIL-produced bytes into a read-write allow buffer.
    fn write_exact(&self, allow_num: usize, source: &[u8]) -> Result<(), ErrorCode> {
        let processid = self.active_processid()?;

        self.apps
            .enter(processid, |_, kernel_data| {
                kernel_data
                    .get_readwrite_processbuffer(allow_num)
                    .and_then(|buffer| {
                        buffer.mut_enter(|destination| {
                            if destination.len() < source.len() {
                                Err(ErrorCode::SIZE)
                            } else {
                                destination[..source.len()].copy_from_slice(source);
                                Ok(())
                            }
                        })
                    })
                    .unwrap_or(Err(ErrorCode::RESERVE))
            })
            .unwrap_or_else(|err| Err(err.into()))
    }
}

impl<A: Aes> AesClient for AesDriver<'_, A> {
    fn read_key(&self, key: &mut [u8]) -> Result<(), ErrorCode> {
        self.read_exact(ro_allow::KEY, key)
    }

    fn read_iv(&self, iv: &mut [u8; BLOCK_SIZE]) -> Result<(), ErrorCode> {
        self.read_exact(ro_allow::IV, iv)
    }

    fn read_ctr(&self, ctr: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_len(ro_allow::COUNTER, ctr)
    }

    fn read_nonce(&self, nonce: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_len(ro_allow::NONCE, nonce)
    }

    fn read_ad(&self, ad: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_len(ro_allow::ASSOCIATED_DATA, ad)
    }

    fn read_input(&self, input: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_len(ro_allow::INPUT, input)
    }

    fn read_tag(&self, tag: &mut [u8]) -> Result<(), ErrorCode> {
        self.read_len(ro_allow::TAG, tag).map(|_| ())
    }

    fn write_iv(&self, iv: &[u8]) -> Result<(), ErrorCode> {
        self.write_exact(rw_allow::IV, iv)
    }

    fn write_output(&self, output: &[u8]) -> Result<(), ErrorCode> {
        self.write_exact(rw_allow::OUTPUT, output)
            .and_then(|()| self.set_active_output_len(output.len()))
    }

    fn write_tag(&self, tag: &[u8]) -> Result<(), ErrorCode> {
        self.write_exact(rw_allow::TAG, tag)
    }

    fn crypt_done(&self, res: Result<(), ErrorCode>) {
        let state = self.state.get();
        self.state.set(State::Idle);

        if let State::Active {
            pid: processid,
            output_len,
        } = state
        {
            let _ = self.apps.enter(processid, |_, kernel_data| {
                let _ = kernel_data
                    .schedule_upcall(upcall::DONE, (into_statuscode(res), output_len, 0));
            });
        }
    }
}

impl<A: Aes> SyscallDriver for AesDriver<'_, A> {
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
