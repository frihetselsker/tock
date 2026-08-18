// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! Component for the mode-specific AES-128 syscall driver.

use capsules_core::driver_mutex::DriverMutex;
use capsules_crypto::aes::Aes128CipherDriver;
use core::mem::MaybeUninit;
use kernel::capabilities::MemoryAllocationCapability;
use kernel::component::Component;
use kernel::hil::crypto::cipher::{Aes128, Cbc, Ccm, Ctr, Ecb, Gcm};

/// Statically allocate a mode-specific AES-128 syscall driver.
#[macro_export]
macro_rules! aes128_cipher_driver_component_static {
    ($CBC:ty, $CCM:ty, $CTR:ty, $ECB:ty, $GCM:ty $(,)?) => {{
        kernel::static_buf!(capsules_crypto::aes::Aes128CipherDriver<$CBC, $CCM, $CTR, $ECB, $GCM>)
    }};
}

pub struct Aes128CipherDriverComponent<
    CBC: Cbc<Aes128> + 'static,
    CCM: Ccm<Aes128> + 'static,
    CTR: Ctr<Aes128> + 'static,
    ECB: Ecb<Aes128> + 'static,
    GCM: Gcm<Aes128> + 'static,
    CAP: MemoryAllocationCapability + 'static,
> {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    cbc: &'static DriverMutex<CBC>,
    ccm: &'static DriverMutex<CCM>,
    ctr: &'static DriverMutex<CTR>,
    ecb: &'static DriverMutex<ECB>,
    gcm: &'static DriverMutex<GCM>,
    mem_cap: CAP,
}

impl<
    CBC: Cbc<Aes128> + 'static,
    CCM: Ccm<Aes128> + 'static,
    CTR: Ctr<Aes128> + 'static,
    ECB: Ecb<Aes128> + 'static,
    GCM: Gcm<Aes128> + 'static,
    CAP: MemoryAllocationCapability + 'static,
> Aes128CipherDriverComponent<CBC, CCM, CTR, ECB, GCM, CAP>
{
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        cbc: &'static DriverMutex<CBC>,
        ccm: &'static DriverMutex<CCM>,
        ctr: &'static DriverMutex<CTR>,
        ecb: &'static DriverMutex<ECB>,
        gcm: &'static DriverMutex<GCM>,
        mem_cap: CAP,
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            cbc,
            ccm,
            ctr,
            ecb,
            gcm,
            mem_cap,
        }
    }
}

impl<
    CBC: Cbc<Aes128> + 'static,
    CCM: Ccm<Aes128> + 'static,
    CTR: Ctr<Aes128> + 'static,
    ECB: Ecb<Aes128> + 'static,
    GCM: Gcm<Aes128> + 'static,
    CAP: MemoryAllocationCapability + 'static,
> Component for Aes128CipherDriverComponent<CBC, CCM, CTR, ECB, GCM, CAP>
{
    type StaticInput = &'static mut MaybeUninit<Aes128CipherDriver<CBC, CCM, CTR, ECB, GCM>>;
    type Output = &'static Aes128CipherDriver<CBC, CCM, CTR, ECB, GCM>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let driver = static_buffer.write(Aes128CipherDriver::new(
            self.cbc,
            self.ccm,
            self.ctr,
            self.ecb,
            self.gcm,
            self.board_kernel
                .create_grant(self.driver_num, &self.mem_cap),
        ));
        assert!(driver.register().is_ok());
        driver
    }
}
