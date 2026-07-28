// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! Component for software AES-128 modes sharing one ECB implementation.

use capsules_core::driver_mutex::{DriverMutex, DriverMutexClient};
use capsules_crypto::sw::sw_cbc::SoftwareCbc;
use capsules_crypto::sw::sw_ccm::SoftwareCcm;
use capsules_crypto::sw::sw_ctr::SoftwareCtr;
use capsules_crypto::sw::sw_gcm::SoftwareGcm;
use core::mem::MaybeUninit;
use kernel::component::Component;
use kernel::deferred_call::DeferredCallClient;
use kernel::hil::crypto::cipher::{Aes128, Ecb};
use kernel::utilities::cells::OptionalCell;

pub type DriverMutexClientCell = OptionalCell<&'static dyn DriverMutexClient>;
pub type EcbMutexType<E> = DriverMutex<E>;
pub type SoftwareCbcType<E> = SoftwareCbc<E>;
pub type SoftwareCcmType<E> = SoftwareCcm<E>;
pub type SoftwareCtrType<E> = SoftwareCtr<E>;
pub type SoftwareGcmType<E> = SoftwareGcm<E>;
pub type SoftwareCbcMutexType<E> = DriverMutex<SoftwareCbc<E>>;
pub type SoftwareCcmMutexType<E> = DriverMutex<SoftwareCcm<E>>;
pub type SoftwareCtrMutexType<E> = DriverMutex<SoftwareCtr<E>>;
pub type SoftwareGcmMutexType<E> = DriverMutex<SoftwareGcm<E>>;

/// Mutex-protected software AES-128 modes built over one ECB implementation.
pub struct SoftwareAes128Modes<E: Ecb<Aes128> + 'static> {
    pub ecb: &'static EcbMutexType<E>,
    pub cbc: &'static SoftwareCbcMutexType<E>,
    pub ccm: &'static SoftwareCcmMutexType<E>,
    pub ctr: &'static SoftwareCtrMutexType<E>,
    pub gcm: &'static SoftwareGcmMutexType<E>,
}

/// Statically allocate all software AES-128 modes and their mutexes.
#[macro_export]
macro_rules! software_aes128_component_static {
    ($E:ty, $clients:expr, $workspace_size:expr $(,)?) => {{
        (
            kernel::static_buf!([$crate::software_aes128::DriverMutexClientCell; 5]),
            kernel::static_buf!([core::mem::MaybeUninit<usize>; 6]),
            kernel::static_buf!($crate::software_aes128::EcbMutexType<$E>),
            kernel::static_buf!([u8; $workspace_size]),
            kernel::static_buf!($crate::software_aes128::SoftwareCbcType<$E>),
            kernel::static_buf!([$crate::software_aes128::DriverMutexClientCell; $clients]),
            kernel::static_buf!([core::mem::MaybeUninit<usize>; $clients + 1]),
            kernel::static_buf!($crate::software_aes128::SoftwareCbcMutexType<$E>),
            kernel::static_buf!([u8; $workspace_size]),
            kernel::static_buf!($crate::software_aes128::SoftwareCcmType<$E>),
            kernel::static_buf!([$crate::software_aes128::DriverMutexClientCell; $clients]),
            kernel::static_buf!([core::mem::MaybeUninit<usize>; $clients + 1]),
            kernel::static_buf!($crate::software_aes128::SoftwareCcmMutexType<$E>),
            kernel::static_buf!([u8; $workspace_size]),
            kernel::static_buf!($crate::software_aes128::SoftwareCtrType<$E>),
            kernel::static_buf!([$crate::software_aes128::DriverMutexClientCell; $clients]),
            kernel::static_buf!([core::mem::MaybeUninit<usize>; $clients + 1]),
            kernel::static_buf!($crate::software_aes128::SoftwareCtrMutexType<$E>),
            kernel::static_buf!([u8; $workspace_size]),
            kernel::static_buf!($crate::software_aes128::SoftwareGcmType<$E>),
            kernel::static_buf!([$crate::software_aes128::DriverMutexClientCell; $clients]),
            kernel::static_buf!([core::mem::MaybeUninit<usize>; $clients + 1]),
            kernel::static_buf!($crate::software_aes128::SoftwareGcmMutexType<$E>),
        )
    }};
}

/// Construct CBC, CCM, CTR, and GCM over a shared mutex-protected ECB driver.
pub struct SoftwareAes128Component<
    E: Ecb<Aes128> + 'static,
    const C: usize,
    const Q: usize,
    const W: usize,
> {
    ecb: &'static E,
}

impl<E: Ecb<Aes128> + 'static, const C: usize, const Q: usize, const W: usize>
    SoftwareAes128Component<E, C, Q, W>
{
    pub fn new(ecb: &'static E) -> Self {
        assert_eq!(C + 1, Q);
        Self { ecb }
    }
}

impl<E: Ecb<Aes128> + 'static, const C: usize, const Q: usize, const W: usize> Component
    for SoftwareAes128Component<E, C, Q, W>
where
    [DriverMutexClientCell; C]: Default,
{
    type StaticInput = (
        &'static mut MaybeUninit<[DriverMutexClientCell; 5]>,
        &'static mut MaybeUninit<[MaybeUninit<usize>; 6]>,
        &'static mut MaybeUninit<EcbMutexType<E>>,
        &'static mut MaybeUninit<[u8; W]>,
        &'static mut MaybeUninit<SoftwareCbcType<E>>,
        &'static mut MaybeUninit<[DriverMutexClientCell; C]>,
        &'static mut MaybeUninit<[MaybeUninit<usize>; Q]>,
        &'static mut MaybeUninit<SoftwareCbcMutexType<E>>,
        &'static mut MaybeUninit<[u8; W]>,
        &'static mut MaybeUninit<SoftwareCcmType<E>>,
        &'static mut MaybeUninit<[DriverMutexClientCell; C]>,
        &'static mut MaybeUninit<[MaybeUninit<usize>; Q]>,
        &'static mut MaybeUninit<SoftwareCcmMutexType<E>>,
        &'static mut MaybeUninit<[u8; W]>,
        &'static mut MaybeUninit<SoftwareCtrType<E>>,
        &'static mut MaybeUninit<[DriverMutexClientCell; C]>,
        &'static mut MaybeUninit<[MaybeUninit<usize>; Q]>,
        &'static mut MaybeUninit<SoftwareCtrMutexType<E>>,
        &'static mut MaybeUninit<[u8; W]>,
        &'static mut MaybeUninit<SoftwareGcmType<E>>,
        &'static mut MaybeUninit<[DriverMutexClientCell; C]>,
        &'static mut MaybeUninit<[MaybeUninit<usize>; Q]>,
        &'static mut MaybeUninit<SoftwareGcmMutexType<E>>,
    );
    type Output = SoftwareAes128Modes<E>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let ecb_clients = static_buffer.0.write(Default::default());
        let ecb_queue = static_buffer.1.write([const { MaybeUninit::uninit() }; 6]);
        let ecb_mutex = static_buffer
            .2
            .write(DriverMutex::new(self.ecb, ecb_clients, ecb_queue));
        DeferredCallClient::register(ecb_mutex);

        let cbc_workspace = static_buffer.3.write([0; W]);
        let software_cbc = static_buffer
            .4
            .write(SoftwareCbc::new(ecb_mutex, cbc_workspace));
        assert!(software_cbc.register().is_ok());
        let cbc_clients = static_buffer.5.write(Default::default());
        let cbc_queue = static_buffer.6.write([const { MaybeUninit::uninit() }; Q]);
        let cbc_mutex =
            static_buffer
                .7
                .write(DriverMutex::new(software_cbc, cbc_clients, cbc_queue));
        DeferredCallClient::register(cbc_mutex);

        let ccm_workspace = static_buffer.8.write([0; W]);
        let software_ccm = static_buffer
            .9
            .write(SoftwareCcm::new(ecb_mutex, ccm_workspace));
        assert!(software_ccm.register().is_ok());
        let ccm_clients = static_buffer.10.write(Default::default());
        let ccm_queue = static_buffer.11.write([const { MaybeUninit::uninit() }; Q]);
        let ccm_mutex =
            static_buffer
                .12
                .write(DriverMutex::new(software_ccm, ccm_clients, ccm_queue));
        DeferredCallClient::register(ccm_mutex);

        let ctr_workspace = static_buffer.13.write([0; W]);
        let software_ctr = static_buffer
            .14
            .write(SoftwareCtr::new(ecb_mutex, ctr_workspace));
        assert!(software_ctr.register().is_ok());
        let ctr_clients = static_buffer.15.write(Default::default());
        let ctr_queue = static_buffer.16.write([const { MaybeUninit::uninit() }; Q]);
        let ctr_mutex =
            static_buffer
                .17
                .write(DriverMutex::new(software_ctr, ctr_clients, ctr_queue));
        DeferredCallClient::register(ctr_mutex);

        let gcm_workspace = static_buffer.18.write([0; W]);
        let software_gcm = static_buffer
            .19
            .write(SoftwareGcm::new(ecb_mutex, gcm_workspace));
        assert!(software_gcm.register().is_ok());
        let gcm_clients = static_buffer.20.write(Default::default());
        let gcm_queue = static_buffer.21.write([const { MaybeUninit::uninit() }; Q]);
        let gcm_mutex =
            static_buffer
                .22
                .write(DriverMutex::new(software_gcm, gcm_clients, gcm_queue));
        DeferredCallClient::register(gcm_mutex);

        SoftwareAes128Modes {
            ecb: ecb_mutex,
            cbc: cbc_mutex,
            ccm: ccm_mutex,
            ctr: ctr_mutex,
            gcm: gcm_mutex,
        }
    }
}
