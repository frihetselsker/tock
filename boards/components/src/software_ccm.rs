// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! Component for a mutex-protected software AES-128 CCM implementation.

use capsules_core::driver_mutex::{DriverMutex, DriverMutexClient};
use capsules_crypto::sw::sw_ccm::SoftwareCcm;
use core::mem::MaybeUninit;
use kernel::component::Component;
use kernel::deferred_call::DeferredCallClient;
use kernel::hil::crypto::cipher::{Aes128, Ecb};
use kernel::utilities::cells::OptionalCell;

pub type DriverMutexClientCell = OptionalCell<&'static dyn DriverMutexClient>;
pub type EcbMutexType<E> = DriverMutex<E>;
pub type SoftwareCcmType<E> = SoftwareCcm<E>;
pub type SoftwareCcmMutexType<E> = DriverMutex<SoftwareCcm<E>>;

/// Statically allocate a software CCM implementation and both mutex layers.
///
/// `$E` is the concrete ECB implementation, `$clients` is the number of
/// clients supported by the outer CCM mutex, and `$workspace_size` is the
/// maximum payload-plus-tag size accepted by the software implementation.
#[macro_export]
macro_rules! software_ccm_component_static {
    ($E:ty, $clients:expr, $workspace_size:expr $(,)?) => {{
        (
            kernel::static_buf!([$crate::software_ccm::DriverMutexClientCell; 1]),
            kernel::static_buf!([core::mem::MaybeUninit<usize>; 2]),
            kernel::static_buf!($crate::software_ccm::EcbMutexType<$E>),
            kernel::static_buf!([u8; $workspace_size]),
            kernel::static_buf!($crate::software_ccm::SoftwareCcmType<$E>),
            kernel::static_buf!([$crate::software_ccm::DriverMutexClientCell; $clients]),
            kernel::static_buf!([core::mem::MaybeUninit<usize>; $clients + 1]),
            kernel::static_buf!($crate::software_ccm::SoftwareCcmMutexType<$E>),
        )
    }};
}

/// Construct `DriverMutex<Ecb> -> SoftwareCcm -> DriverMutex<SoftwareCcm>`.
pub struct SoftwareCcmComponent<
    E: Ecb<Aes128> + 'static,
    const C: usize,
    const Q: usize,
    const W: usize,
> {
    ecb: &'static E,
}

impl<E: Ecb<Aes128> + 'static, const C: usize, const Q: usize, const W: usize>
    SoftwareCcmComponent<E, C, Q, W>
{
    pub fn new(ecb: &'static E) -> Self {
        assert_eq!(C + 1, Q);
        Self { ecb }
    }
}

impl<E: Ecb<Aes128> + 'static, const C: usize, const Q: usize, const W: usize> Component
    for SoftwareCcmComponent<E, C, Q, W>
where
    [DriverMutexClientCell; C]: Default,
{
    type StaticInput = (
        &'static mut MaybeUninit<[DriverMutexClientCell; 1]>,
        &'static mut MaybeUninit<[MaybeUninit<usize>; 2]>,
        &'static mut MaybeUninit<EcbMutexType<E>>,
        &'static mut MaybeUninit<[u8; W]>,
        &'static mut MaybeUninit<SoftwareCcmType<E>>,
        &'static mut MaybeUninit<[DriverMutexClientCell; C]>,
        &'static mut MaybeUninit<[MaybeUninit<usize>; Q]>,
        &'static mut MaybeUninit<SoftwareCcmMutexType<E>>,
    );
    type Output = &'static SoftwareCcmMutexType<E>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let ecb_clients = static_buffer.0.write(Default::default());
        let ecb_queue = static_buffer.1.write([const { MaybeUninit::uninit() }; 2]);
        let ecb_mutex = static_buffer
            .2
            .write(DriverMutex::new(self.ecb, ecb_clients, ecb_queue));
        DeferredCallClient::register(ecb_mutex);

        let workspace = static_buffer.3.write([0; W]);
        let software_ccm = static_buffer
            .4
            .write(SoftwareCcm::new(ecb_mutex, workspace));
        assert!(software_ccm.register().is_ok());

        let ccm_clients = static_buffer.5.write(Default::default());
        let ccm_queue = static_buffer.6.write([const { MaybeUninit::uninit() }; Q]);
        let ccm_mutex =
            static_buffer
                .7
                .write(DriverMutex::new(software_ccm, ccm_clients, ccm_queue));
        DeferredCallClient::register(ccm_mutex);

        ccm_mutex
    }
}
