// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Component for IEEE 802.15.4 radio syscall interface.
//!
//! This provides one Component, `Ieee802154Component`, which implements a
//! userspace syscall interface to a full 802.15.4 stack with a always-on MAC
//! implementation, as well as multiplexed access to that MAC implementation.
//!
//! Usage
//! -----
//! ```rust
//! let ccm_mutex = components::software_ccm::SoftwareCcmComponent::new(
//!     &base_peripherals.ecb,
//! )
//! .finalize(components::software_ccm_component_static!(
//!     nrf52840::ecb::Ecb,
//!     1,
//!     components::ieee802154::CCM_WORKSPACE_SIZE,
//! ));
//!
//! let (radio, mux_mac) = components::ieee802154::Ieee802154Component::new(
//!     board_kernel,
//!     capsules_extra::ieee802154::DRIVER_NUM,
//!     &nrf52::ieee802154_radio::RADIO,
//!     ccm_mutex,
//!     PAN_ID,
//!     SRC_MAC,
//!     deferred_caller,
//! )
//! .finalize(components::ieee802154_component_static!(
//!     nrf52::ieee802154_radio::Radio,
//!     components::software_ccm::SoftwareCcmType<nrf52840::ecb::Ecb>
//! ));
//! ```

use capsules_core::driver_mutex::DriverMutex;
use capsules_extra::ieee802154::device::MacDevice;
use capsules_extra::ieee802154::mac::{AwakeMac, Mac};
use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;
use kernel::hil::crypto::cipher::{Aes128, Ccm};
use kernel::hil::radio::{self, MAX_BUF_SIZE};

pub const CCM_WORKSPACE_SIZE: usize = radio::MAX_BUF_SIZE + 16;

// Setup static space for the objects.
#[macro_export]
macro_rules! ieee802154_component_static {
    ($R:ty, $C:ty $(,)?) => {{
        let awake_mac = kernel::static_buf!(capsules_extra::ieee802154::mac::AwakeMac<'static, $R>);
        let framer = kernel::static_buf!(
            capsules_extra::ieee802154::framer::Framer<
                'static,
                capsules_extra::ieee802154::mac::AwakeMac<'static, $R>,
                $C,
            >
        );

        let mux_mac = kernel::static_buf!(
            capsules_extra::ieee802154::virtual_mac::MuxMac<
                'static,
                capsules_extra::ieee802154::framer::Framer<
                    'static,
                    capsules_extra::ieee802154::mac::AwakeMac<'static, $R>,
                    $C,
                >,
            >
        );
        let mac_user = kernel::static_buf!(
            capsules_extra::ieee802154::virtual_mac::MacUser<
                'static,
                capsules_extra::ieee802154::framer::Framer<
                    'static,
                    capsules_extra::ieee802154::mac::AwakeMac<'static, $R>,
                    $C,
                >,
            >
        );
        let radio_driver = kernel::static_buf!(
            capsules_extra::ieee802154::RadioDriver<
                'static,
                capsules_extra::ieee802154::virtual_mac::MacUser<
                    'static,
                    capsules_extra::ieee802154::framer::Framer<
                        'static,
                        capsules_extra::ieee802154::mac::AwakeMac<'static, $R>,
                        $C,
                    >,
                >,
            >
        );

        let radio_buf = kernel::static_buf!([u8; kernel::hil::radio::MAX_BUF_SIZE]);
        let radio_rx_buf = kernel::static_buf!([u8; kernel::hil::radio::MAX_BUF_SIZE]);
        let radio_rx_crypt_buf = kernel::static_buf!([u8; kernel::hil::radio::MAX_BUF_SIZE]);

        (
            awake_mac,
            framer,
            mux_mac,
            mac_user,
            radio_driver,
            radio_buf,
            radio_rx_buf,
            radio_rx_crypt_buf,
        )
    };};
}

pub type Ieee802154ComponentType<R, C> = capsules_extra::ieee802154::RadioDriver<
    'static,
    capsules_extra::ieee802154::virtual_mac::MacUser<
        'static,
        capsules_extra::ieee802154::framer::Framer<
            'static,
            capsules_extra::ieee802154::mac::AwakeMac<'static, R>,
            C,
        >,
    >,
>;

pub type Ieee802154ComponentMacDeviceType<R, C> = capsules_extra::ieee802154::framer::Framer<
    'static,
    capsules_extra::ieee802154::mac::AwakeMac<'static, R>,
    C,
>;

pub struct Ieee802154Component<
    R: 'static + kernel::hil::radio::Radio<'static>,
    C: Ccm<Aes128> + 'static,
> {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    radio: &'static R,
    ccm_mutex: &'static DriverMutex<C>,
    pan_id: capsules_extra::net::ieee802154::PanID,
    short_addr: u16,
    long_addr: [u8; 8],
}

impl<R: 'static + kernel::hil::radio::Radio<'static>, C: Ccm<Aes128> + 'static>
    Ieee802154Component<R, C>
{
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        radio: &'static R,
        ccm_mutex: &'static DriverMutex<C>,
        pan_id: capsules_extra::net::ieee802154::PanID,
        short_addr: u16,
        long_addr: [u8; 8],
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            radio,
            ccm_mutex,
            pan_id,
            short_addr,
            long_addr,
        }
    }
}

impl<R: 'static + kernel::hil::radio::Radio<'static>, C: Ccm<Aes128> + 'static> Component
    for Ieee802154Component<R, C>
{
    type StaticInput = (
        &'static mut MaybeUninit<capsules_extra::ieee802154::mac::AwakeMac<'static, R>>,
        &'static mut MaybeUninit<
            capsules_extra::ieee802154::framer::Framer<'static, AwakeMac<'static, R>, C>,
        >,
        &'static mut MaybeUninit<
            capsules_extra::ieee802154::virtual_mac::MuxMac<
                'static,
                capsules_extra::ieee802154::framer::Framer<'static, AwakeMac<'static, R>, C>,
            >,
        >,
        &'static mut MaybeUninit<
            capsules_extra::ieee802154::virtual_mac::MacUser<
                'static,
                capsules_extra::ieee802154::framer::Framer<'static, AwakeMac<'static, R>, C>,
            >,
        >,
        &'static mut MaybeUninit<
            capsules_extra::ieee802154::RadioDriver<
                'static,
                capsules_extra::ieee802154::virtual_mac::MacUser<
                    'static,
                    capsules_extra::ieee802154::framer::Framer<'static, AwakeMac<'static, R>, C>,
                >,
            >,
        >,
        &'static mut MaybeUninit<[u8; radio::MAX_BUF_SIZE]>,
        &'static mut MaybeUninit<[u8; radio::MAX_BUF_SIZE]>,
        &'static mut MaybeUninit<[u8; radio::MAX_BUF_SIZE]>,
    );
    type Output = (
        &'static capsules_extra::ieee802154::RadioDriver<
            'static,
            capsules_extra::ieee802154::virtual_mac::MacUser<
                'static,
                capsules_extra::ieee802154::framer::Framer<'static, AwakeMac<'static, R>, C>,
            >,
        >,
        &'static capsules_extra::ieee802154::virtual_mac::MuxMac<
            'static,
            capsules_extra::ieee802154::framer::Framer<'static, AwakeMac<'static, R>, C>,
        >,
    );

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);

        // Keeps the radio on permanently; pass-through layer.
        let radio_rx_buf = static_buffer.6.write([0; radio::MAX_BUF_SIZE]);
        let awake_mac = static_buffer.0.write(AwakeMac::new(self.radio));
        self.radio.set_transmit_client(awake_mac);
        self.radio.set_receive_client(awake_mac);
        self.radio.set_receive_buffer(radio_rx_buf);

        let radio_rx_crypt_buf = static_buffer.7.write([0; MAX_BUF_SIZE]);

        let mac_device = static_buffer
            .1
            .write(capsules_extra::ieee802154::framer::Framer::new(
                awake_mac,
                self.ccm_mutex,
                kernel::utilities::leasable_buffer::SubSliceMut::new(radio_rx_crypt_buf),
            ));
        assert!(mac_device.register().is_ok());
        awake_mac.set_transmit_client(mac_device);
        awake_mac.set_receive_client(mac_device);
        awake_mac.set_config_client(mac_device);

        let mux_mac = static_buffer
            .2
            .write(capsules_extra::ieee802154::virtual_mac::MuxMac::new(
                mac_device,
            ));
        mac_device.set_transmit_client(mux_mac);
        mac_device.set_receive_client(mux_mac);

        let userspace_mac =
            static_buffer
                .3
                .write(capsules_extra::ieee802154::virtual_mac::MacUser::new(
                    mux_mac,
                ));
        mux_mac.add_user(userspace_mac);

        let radio_buffer = static_buffer.5.write([0; radio::MAX_BUF_SIZE]);
        let radio_driver = static_buffer
            .4
            .write(capsules_extra::ieee802154::RadioDriver::new(
                userspace_mac,
                self.board_kernel.create_grant(self.driver_num, &grant_cap),
                radio_buffer,
            ));
        kernel::deferred_call::DeferredCallClient::register(radio_driver);

        mac_device.set_key_procedure(radio_driver);
        mac_device.set_device_procedure(radio_driver);
        userspace_mac.set_transmit_client(radio_driver);
        userspace_mac.set_receive_client(radio_driver);
        userspace_mac.set_pan(self.pan_id);
        userspace_mac.set_address(self.short_addr);
        userspace_mac.set_address_long(self.long_addr);

        (radio_driver, mux_mac)
    }
}

// IEEE 802.15.4 RAW DRIVER

// Setup static space for the objects.
#[macro_export]
macro_rules! ieee802154_raw_component_static {
    ($R:ty $(,)?) => {{
        let radio_driver =
            kernel::static_buf!(capsules_extra::ieee802154::phy_driver::RadioDriver<$R>);
        let tx_buffer = kernel::static_buf!([u8; kernel::hil::radio::MAX_BUF_SIZE]);
        let rx_buffer = kernel::static_buf!([u8; kernel::hil::radio::MAX_BUF_SIZE]);

        (radio_driver, tx_buffer, rx_buffer)
    };};
}

pub type Ieee802154RawComponentType<R> =
    capsules_extra::ieee802154::phy_driver::RadioDriver<'static, R>;

pub struct Ieee802154RawComponent<R: 'static + kernel::hil::radio::Radio<'static>> {
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    radio: &'static R,
}

impl<R: 'static + kernel::hil::radio::Radio<'static>> Ieee802154RawComponent<R> {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        radio: &'static R,
    ) -> Self {
        Self {
            board_kernel,
            driver_num,
            radio,
        }
    }
}

impl<R: 'static + kernel::hil::radio::Radio<'static>> Component for Ieee802154RawComponent<R> {
    type StaticInput = (
        &'static mut MaybeUninit<capsules_extra::ieee802154::phy_driver::RadioDriver<'static, R>>,
        &'static mut MaybeUninit<[u8; radio::MAX_BUF_SIZE]>,
        &'static mut MaybeUninit<[u8; radio::MAX_BUF_SIZE]>,
    );
    type Output = &'static capsules_extra::ieee802154::phy_driver::RadioDriver<'static, R>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);

        let tx_buffer = static_buffer.1.write([0; MAX_BUF_SIZE]);
        let radio_rx_buf = static_buffer.2.write([0; radio::MAX_BUF_SIZE]);

        let radio_driver =
            static_buffer
                .0
                .write(capsules_extra::ieee802154::phy_driver::RadioDriver::new(
                    self.radio,
                    self.board_kernel.create_grant(self.driver_num, &grant_cap),
                    tx_buffer,
                ));

        self.radio.set_transmit_client(radio_driver);
        self.radio.set_receive_client(radio_driver);
        self.radio.set_receive_buffer(radio_rx_buf);

        radio_driver
    }
}
