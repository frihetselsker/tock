// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! Test the implementation of Hmac driver by performing a hash
//! and checking it against the expected hash value.

use core::cell::Cell;

use capsules_core::driver_mutex::{
    DriverMutex, DriverMutexAny, DriverMutexClient, DriverMutexHandle, DriverMutexRef,
};
use capsules_core::test::capsule_test::{CapsuleTest, CapsuleTestClient};
use kernel::deferred_call::{DeferredCall, DeferredCallClient};
use kernel::hil::crypto::digest::{Client, HmacClient, Mode, TransferMode};
use kernel::hil::crypto::{self, digest};
use kernel::utilities::cells::{MapCell, OptionalCell, TakeCell};
use kernel::utilities::leasable_buffer::{SubSliceMut, SubSliceMutImmut};
use kernel::{ErrorCode, debug};

pub struct TestHmac<H: crypto::digest::Hmac + 'static> {
    hmac_mutex: &'static DriverMutex<H>,
    hmac_handle: OptionalCell<DriverMutexHandle>,
    hmac: MapCell<DriverMutexRef<H>>,
    mode: Cell<Mode>,
    transfer_mode: Cell<TransferMode>,
    input_buffer: TakeCell<'static, [u8]>,
    output_buffer: TakeCell<'static, [u8]>,
    key_buffer: TakeCell<'static, [u8]>,
    input_len: Cell<usize>,
    output_len: Cell<usize>,
    key_len: Cell<usize>,
    input_offset: Cell<usize>,
    output_offset: Cell<usize>,
    key_offset: Cell<usize>,
    deferred_call: DeferredCall,
    client: OptionalCell<&'static dyn CapsuleTestClient>,
}

const CHUNK_SIZE: usize = 32;

impl<H: crypto::digest::Hmac> TestHmac<H> {
    pub fn new(
        hmac_mutex: &'static DriverMutex<H>,
        mode: Mode,
        input_buffer: &'static mut [u8],
        output_buffer: &'static mut [u8],
        key_buffer: &'static mut [u8],
    ) -> TestHmac<H> {
        TestHmac {
            hmac_mutex,
            hmac_handle: OptionalCell::empty(),
            hmac: MapCell::empty(),
            mode: Cell::new(mode),
            transfer_mode: Cell::new(TransferMode::default()),
            input_buffer: TakeCell::new(input_buffer),
            output_buffer: TakeCell::new(output_buffer),
            key_buffer: TakeCell::new(key_buffer),
            input_len: Cell::new(0),
            output_len: Cell::new(0),
            key_len: Cell::new(0),
            input_offset: Cell::new(0),
            output_offset: Cell::new(0),
            key_offset: Cell::new(0),
            deferred_call: DeferredCall::new(),
            client: OptionalCell::empty(),
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

    fn read_input(&self, destination: &mut [u8]) -> Result<usize, ErrorCode> {
        self.input_buffer.map_or(Err(ErrorCode::FAIL), |source| {
            let offset = self.input_offset.get();
            if offset >= source.len() || destination.is_empty() {
                panic!("HmacTest: Either destination is empty or offset got bigger than the actual size of input buffer, offset: {}, input size: {}", offset, source.len());
            }
            let read_len = destination.len().min(source.len() - offset);
            destination[..read_len].copy_from_slice(&source[offset..offset + read_len]);
            self.input_offset.set(offset + read_len);
            Ok(read_len)
        })
    }

    fn read_key(&self, destination: &mut [u8]) -> Result<usize, ErrorCode> {
        self.key_buffer.map_or(Err(ErrorCode::FAIL), |source| {
            let offset = self.key_offset.get();
            if offset >= source.len() || destination.is_empty() {
                panic!("HmacTest: Either destination is empty or offset got bigger than the actual size of key buffer, offset: {}, input size: {}", offset, source.len());
            }
            let read_len = destination.len().min(source.len() - offset);
            destination[..read_len].copy_from_slice(&source[offset..offset + read_len]);
            self.key_offset.set(offset + read_len);
            Ok(read_len)
        })
    }

    fn write_output(&self, source: &[u8]) -> Result<(), ErrorCode> {
        // The correct hash value will be checked here.
        self.output_buffer
            .map_or(Err(ErrorCode::FAIL), |destination| {
                let offset = self.output_offset.get();
                let end = offset.checked_add(source.len()).ok_or(ErrorCode::SIZE)?;
                if end > destination.len() {
                    panic!("HmacTest: offset got bigger than the actual size of output buffer, offset: {}, input size: {}", offset, destination.len());
                }
                for i in 0..source.len() {
                    if destination[offset + i] != source[i] {
                        panic!(
                            "HmacTest: Verification failed at byte 0x{:02x}, index {}",
                            destination[offset + i],
                            offset + i
                        );
                    }
                }

                self.output_offset.set(offset + source.len());
                Ok(())
            })
    }

    pub fn run(&self) -> Result<(), ErrorCode> {
        if self.hmac_handle.is_none() {
            return Err(ErrorCode::OFF);
        }

        let r = self.input_buffer.map_or(Err(ErrorCode::FAIL), |buf| {
            self.input_len.set(buf.len());
            Ok(())
        });
        if r.is_err() {
            panic!("HmacTest: input buffer is missing");
        }
        let r = self.output_buffer.map_or(Err(ErrorCode::FAIL), |buf| {
            let len = buf.len();
            if len != self.mode.get().get_digest_len() {
                panic!("HmacTest: output buffer is incomaptible with the set mode, expected: {} bytes, got: {} bytes", self.mode.get().get_digest_len(), len);
            }
            self.output_len.set(len);
            Ok(())
        });
        if r.is_err() {
            panic!("HmacTest: output buffer is missing");
        }
        self.input_offset.set(0);
        self.output_offset.set(0);

        if let Err(error) = self.hmac_handle.map_or(Err(ErrorCode::OFF), |handle| {
            self.hmac_mutex.request(handle)
        }) {
            panic!(
                "HmacTest: failed to request access to hmac peripheral, error: {:?}",
                error
            );
        }
        Ok(())
    }

    fn finish(&self, result: Result<(), ErrorCode>) {
        self.hmac.take().and_then(|hmac| {
            hmac.clear_data();
            Some(hmac)
        });

        if let Err(e) = result {
            panic!(
                "HmacTest: verification passed, but there was an error from the driver side: {:?}",
                e
            );
        } else {
            debug!("HmacTest: Verification was successful!");
            self.client.map(|client| {
                client.done(Ok(()));
            });
        }
    }

    fn handle_dma_buffer(&self) -> Result<SubSliceMut<'static, u8>, ErrorCode> {
        let offset = self.input_offset.get();
        self.input_buffer
            .take()
            .map_or(Err(ErrorCode::FAIL), |buf| {
                let chunk_size = CHUNK_SIZE.min(buf.len() - offset);
                offset.checked_add(chunk_size).ok_or(ErrorCode::SIZE)?;
                let mut lease_buf = SubSliceMut::new(buf);
                lease_buf.slice(offset..offset + chunk_size);
                Ok(lease_buf)
            })
    }
}

impl<H: crypto::digest::Hmac> DriverMutexClient for TestHmac<H> {
    fn ready(&'static self, resource: DriverMutexAny) {
        let result = match resource.downcast::<H>() {
            Ok(hmac) => {
                hmac.set_client(self);
                self.hmac.put(hmac);
                self.hmac.map_or(Err(ErrorCode::FAIL), |hmac| {
                    hmac.authenticate(self.mode.get(), self.input_len.get(), self.key_len.get())
                        .and_then(|transfer_mode| {
                            self.transfer_mode.set(transfer_mode);
                            Ok(())
                        })
                })
            }
            Err(_) => Err(ErrorCode::INVAL),
        };

        if let Err(error) = result {
            panic!("HmacTest: operation didn't start, error: {:?}", error);
        }
    }
}

impl<H: crypto::digest::Hmac> Client for TestHmac<H> {
    fn read_input(&self, input: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_input(input)
    }

    fn write_output(&self, output: &[u8]) -> Result<(), ErrorCode> {
        self.write_output(output)
    }

    fn dma_buffer_done(
        &self,
        result: Result<(), ErrorCode>,
        dma_buffer: kernel::utilities::leasable_buffer::SubSliceMutImmut<'static, u8>,
    ) {
        if let SubSliceMutImmut::Mutable(s) = dma_buffer {
            self.input_buffer.replace(s.take());
            if let Err(error) = result {
                panic!(
                    "HmacTest: peripheral didn't manage to send contents of DMA buffer, error: {:?}",
                    error
                );
            }
            if self.input_offset.get() < self.input_len.get() {
                let result = self.hmac.map_or(Err(ErrorCode::FAIL), |hmac| {
                    let lease_buf = self.handle_dma_buffer()?;
                    hmac.feed_dma_buffer(SubSliceMutImmut::Mutable(lease_buf))
                        .map_err(|(e, buf)| {
                            match buf {
                                SubSliceMutImmut::Immutable(_) => unreachable!(),
                                SubSliceMutImmut::Mutable(sub_slice_mut) => {
                                    self.input_buffer.replace(sub_slice_mut.take());
                                }
                            }
                            e
                        })
                });
                if let Err(error) = result {
                    panic!(
                        "HmacTest: DMA buffer was failed to be sent, error: {:?}",
                        error
                    );
                }
            }
        }
    }

    fn hash_done(&self, result: Result<(), ErrorCode>) {
        self.finish(result)
    }
}

impl<H: digest::Hmac> HmacClient for TestHmac<H> {
    fn read_key(&self, key: &mut [u8]) -> Result<usize, ErrorCode> {
        let Ok(bytes_read) = self.read_key(key) else {
            panic!("HmacTest: failed to read key");
        };
        if self.key_len.get() == self.key_offset.get()
            && matches!(self.transfer_mode.get(), TransferMode::DMA)
        {
            self.deferred_call.set();
        }
        Ok(bytes_read)
    }
}

impl<H: digest::Hmac> DeferredCallClient for TestHmac<H> {
    fn handle_deferred_call(&'static self) {
        // This can be called only if DMA is used
        // and key has already been read by the driver.
        let result = self.hmac.map_or(Err(ErrorCode::FAIL), |hmac| {
            let lease_buf = self.handle_dma_buffer()?;
            hmac.feed_dma_buffer(SubSliceMutImmut::Mutable(lease_buf))
                .map_err(|(e, buf)| {
                    match buf {
                        SubSliceMutImmut::Immutable(_) => unreachable!(),
                        SubSliceMutImmut::Mutable(sub_slice_mut) => {
                            self.input_buffer.replace(sub_slice_mut.take());
                        }
                    }
                    e
                })
        });
        if let Err(error) = result {
            panic!("HmacTest: DMA buffer failed to be sent: {:?}", error);
        }
    }

    fn register(&'static self) {
        self.deferred_call.register(self);
    }
}

impl<H: digest::Hmac> CapsuleTest for TestHmac<H> {
    fn set_client(&self, client: &'static dyn CapsuleTestClient) {
        self.client.set(client);
    }
}
