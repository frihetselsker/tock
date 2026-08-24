// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

use capsules_core::driver_mutex::DriverMutex;
use capsules_crypto::hash::Hash;
use core::mem::MaybeUninit;
use kernel::capabilities::MemoryAllocationCapability;
use kernel::component::Component;
use kernel::hil::crypto::digest;

// Setup static space for the objects.
#[macro_export]
macro_rules! hash_crypto_component_static {
    ($H:ty $(,)?) => {{ kernel::static_buf!(capsules_crypto::hash::Hash<$H>) }};
}

pub struct HashComponent<H: 'static + digest::Digest, CAP: MemoryAllocationCapability + 'static> {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    hash: &'static DriverMutex<H>,
    mem_cap: CAP,
}

impl<H: 'static + digest::Digest, CAP: MemoryAllocationCapability + 'static> HashComponent<H, CAP> {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        hash: &'static DriverMutex<H>,
        mem_cap: CAP,
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            hash,
            mem_cap,
        }
    }
}

impl<H: 'static + digest::Digest, CAP: MemoryAllocationCapability + 'static> Component
    for HashComponent<H, CAP>
{
    type StaticInput = &'static mut MaybeUninit<Hash<H>>;

    type Output = &'static Hash<H>;

    fn finalize(self, s: Self::StaticInput) -> Self::Output {
        s.write(Hash::new(
            self.hash,
            self.board_kernel
                .create_grant(self.driver_num, &self.mem_cap),
        ))
    }
}
