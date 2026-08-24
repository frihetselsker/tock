// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

use capsules_core::driver_mutex::DriverMutex;
use capsules_crypto::hmac::Hmac;
use core::mem::MaybeUninit;
use kernel::capabilities::MemoryAllocationCapability;
use kernel::component::Component;
use kernel::hil::crypto::digest;

#[macro_export]
macro_rules! hmac_crypto_component_static {
    ($H:ty $(,)?) => {{ kernel::static_buf!(capsules_crypto::hmac::Hmac<$H>) }};
}

pub struct HmacComponent<H: 'static + digest::Hmac, CAP: MemoryAllocationCapability + 'static> {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    hmac: &'static DriverMutex<H>,
    mem_cap: CAP,
}

impl<H: 'static + digest::Hmac, CAP: MemoryAllocationCapability + 'static> HmacComponent<H, CAP> {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        hmac: &'static DriverMutex<H>,
        mem_cap: CAP,
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            hmac,
            mem_cap,
        }
    }
}

impl<H: 'static + digest::Hmac, CAP: MemoryAllocationCapability + 'static> Component
    for HmacComponent<H, CAP>
{
    type StaticInput = &'static mut MaybeUninit<Hmac<H>>;

    type Output = &'static Hmac<H>;

    fn finalize(self, s: Self::StaticInput) -> Self::Output {
        s.write(Hmac::new(
            self.hmac,
            self.board_kernel
                .create_grant(self.driver_num, &self.mem_cap),
        ))
    }
}
