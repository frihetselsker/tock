// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2024.
// Copyright OxidOS Automotive 2026.

#![no_std]
#![no_main]

use core::cell::Cell;
use kernel::capabilities::{self, MemoryAllocationCapability};
use kernel::component::Component;
use kernel::debug;
use kernel::debug::PanicResources;
use kernel::hil::crypto::elliptic_curves::ecc_math::{EccClient, EccCrypto, VerifyEccPoint};
use kernel::hil::gpio::{Configure, Output};
use kernel::hil::public_key_crypto::rsa_math::RsaCryptoBase;
use kernel::hil::symmetric_encryption::AES256;
use kernel::platform::chip::Chip;
use kernel::platform::{KernelResources, SyscallDriverLookup};
use kernel::utilities::cells::TakeCell;
use kernel::utilities::single_thread_value::SingleThreadValue;
use kernel::{create_capability, static_init};

use stm32u545::gpio::PinId;
use stm32u545::hash::hash::FIFO_SIZE;
use stm32u545::pkc;
use stm32u545::rng::RNG_BASE;

use kernel::hil::crypto::modular_arithmetic::{MathClient, MathCryptoBase};
use stm32u545::pkc::constants::SupportedOp;

pub mod io;

// ==============================================================================
// TEST VARIABLES FOR PKA
// Modify these variables to test different operations. They are placed here
// for obvious visibility and easy modification.
// ==============================================================================

kernel::stack_size! {0x2000}

/// Hardcoded scalar to multiply the doubled point (k = 3)
const TEST_ECC_SCALAR: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
];

/// Modulus for modular arithmetic (Math tests): 2^256 - 7
const TEST_MATH_MODULUS: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF9,
];

/// Operand A for modular arithmetic
const TEST_MATH_A: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
];

/// Operand B for modular arithmetic
const TEST_MATH_B: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
];

// ===================== Expected values (computed offline) =====================

/// 32-byte big-endian encoding of a small number.
const fn small(v: u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[31] = v;
    a
}

/// (A + B) mod p = 12
const EXPECTED_MATH_ADD: [u8; 32] = small(0x0c);
/// (A * B) mod p = 35
const EXPECTED_MATH_MUL: [u8; 32] = small(0x23);
/// A^-1 mod p, where the first operand fed for Inverse is p + 5 (== 5 mod p)
const EXPECTED_MATH_INV: [u8; 32] = {
    let mut a = [0x33u8; 32];
    a[31] = 0x32;
    a
};
/// (p + 5) mod p = 5
const EXPECTED_MATH_MOD: [u8; 32] = small(0x05);

/// 2G (X || Y)
const EXPECTED_2G: [u8; 64] = [
    0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e, 0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5, 0x1a, 0xc3,
    0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35, 0xa6, 0x0b, 0x48, 0xfc, 0x47, 0x66, 0x99, 0x78,
    0x07, 0x77, 0x55, 0x10, 0xdb, 0x8e, 0xd0, 0x40, 0x29, 0x3d, 0x9a, 0xc6, 0x9f, 0x74, 0x30, 0xdb,
    0xba, 0x7d, 0xad, 0xe6, 0x3c, 0xe9, 0x82, 0x29, 0x9e, 0x04, 0xb7, 0x9d, 0x22, 0x78, 0x73, 0xd1,
];

/// 6G = 3 * 2G (X || Y)
const EXPECTED_6G: [u8; 64] = [
    0xb0, 0x1a, 0x17, 0x2a, 0x76, 0xa4, 0x60, 0x2c, 0x92, 0xd3, 0x24, 0x2c, 0xb8, 0x97, 0xdd, 0xe3,
    0x02, 0x4c, 0x74, 0x0d, 0xeb, 0xb2, 0x15, 0xb4, 0xc6, 0xb0, 0xaa, 0xe9, 0x3c, 0x22, 0x91, 0xa9,
    0xe8, 0x5c, 0x10, 0x74, 0x32, 0x37, 0xda, 0xd5, 0x6f, 0xec, 0x0e, 0x2d, 0xfb, 0xa7, 0x03, 0x79,
    0x1c, 0x00, 0xf7, 0x70, 0x1c, 0x7e, 0x16, 0xbd, 0xfd, 0x7c, 0x48, 0x53, 0x8f, 0xc7, 0x7f, 0xe2,
];

/// 8G = 2G + 6G (X || Y)
const EXPECTED_8G: [u8; 64] = [
    0x62, 0xd9, 0x77, 0x9d, 0xbe, 0xe9, 0xb0, 0x53, 0x40, 0x42, 0x74, 0x2d, 0x3a, 0xb5, 0x4c, 0xad,
    0xc1, 0xd2, 0x38, 0x98, 0x0f, 0xce, 0x97, 0xdb, 0xb4, 0xdd, 0x9d, 0xc1, 0xdb, 0x6f, 0xb3, 0x93,
    0xad, 0x5a, 0xcc, 0xbd, 0x91, 0xe9, 0xd8, 0x24, 0x4f, 0xf1, 0x5d, 0x77, 0x11, 0x67, 0xce, 0xe0,
    0xa2, 0xed, 0x51, 0xf6, 0xbb, 0xe7, 0x6a, 0x78, 0xda, 0x54, 0x0a, 0x6a, 0x0f, 0x09, 0x95, 0x7e,
];

/// Fixed pseudo-random bytes, used as a "point" that is not on the curve.
const NOT_A_POINT: [u8; 64] = [
    0x3a, 0x91, 0x5c, 0xe7, 0x08, 0x4d, 0xb2, 0x6f, 0xd1, 0x27, 0x9e, 0x44, 0xa8, 0x13, 0x7c, 0xf5,
    0x62, 0x0b, 0xc9, 0x35, 0x8e, 0xda, 0x71, 0x19, 0xf0, 0x4b, 0x86, 0x2d, 0xe3, 0x5a, 0x97, 0xc4,
    0x1e, 0xb7, 0x53, 0x88, 0x2f, 0xd4, 0x60, 0xa1, 0x9b, 0x3c, 0xee, 0x75, 0x0d, 0xc2, 0x49, 0xf6,
    0x84, 0x2a, 0x6d, 0xb0, 0x17, 0xe9, 0x5f, 0x33, 0xca, 0x78, 0x01, 0xdd, 0x92, 0x4e, 0xa5, 0x6b,
];

/// RSA test: base = 0x1234567890abcdef
const TEST_RSA_MESSAGE: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
];

/// RSA test: exponent = 0x10001
const TEST_RSA_EXPONENT: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
];

/// RSA test: base ^ 0x10001 mod (2^256 - 7)
const EXPECTED_RSA_RESULT: [u8; 32] = [
    0xd8, 0x25, 0x93, 0x4b, 0x21, 0x05, 0xbd, 0xbb, 0xb4, 0x2b, 0x92, 0xc1, 0xf4, 0x22, 0xb2, 0x3e,
    0x93, 0xb4, 0x2d, 0xe7, 0x19, 0x2d, 0xe8, 0x72, 0x05, 0xda, 0xb6, 0x91, 0x33, 0x6f, 0xcc, 0x38,
];

/// Panics (after printing both values) if `got != want`.
fn expect(name: &str, got: &[u8], want: &[u8]) {
    if got == want {
        debug!("[PASS] {}", name);
    } else {
        debug!(
            "[FAIL] {}\n  got:  {:02x?}\n  want: {:02x?}",
            name, got, want
        );
        panic!("test failed: {}", name);
    }
}
// ==============================================================================

extern "C" {
    static _sappmem: u8;
    static _eappmem: u8;
}

const NUM_PROCS: usize = 4;

type GpioHw = stm32u545::gpio::Pin<'static>;
type ChipHw =
    stm32u545::chip::Stm32u5xx<'static, stm32u545::chip::Stm32u5xxDefaultPeripherals<'static>>;
type ProcessPrinterInUse = capsules_system::process_printer::ProcessPrinterText;

type GpioDriver = components::gpio::GpioComponentType<GpioHw>;

static PANIC_RESOURCES: SingleThreadValue<PanicResources<ChipHw, ProcessPrinterInUse>> =
    SingleThreadValue::new();

#[derive(Copy, Clone, PartialEq)]
enum TestState {
    EccWaitDoubling,
    EccWaitMul,
    EccWaitAdd,
    MathWaitAdd,
    MathWaitMul,
    MathWaitDiv,
    MathWaitMod,
    // --- new ---
    /// verify_point on random bytes, expecting INVAL
    VerifyWaitBad,
    /// verify_point on the doubled point, expecting Ok
    VerifyWaitGood,
    /// RSA modular exponentiation
    RsaWaitModExp,
    Done,
}

struct PkaTester<'a> {
    pka: &'a pkc::pka::Pka<'a>,
    state: Cell<TestState>,

    // ECC variables
    point_doubled: Cell<[u8; 64]>,
    point_mul: Cell<[u8; 64]>,
    ecc_output: Cell<[u8; 64]>,
    out_done: Cell<usize>,

    // Math variables
    math_output: Cell<[u8; 32]>,
    math_read_count: Cell<u8>,

    // RSA buffers (set with `set_rsa_buffers`)
    rsa_message: TakeCell<'static, [u8]>,
    rsa_result: TakeCell<'static, [u8]>,
}

impl<'a> PkaTester<'a> {
    fn new(pka: &'a pkc::pka::Pka<'a>) -> Self {
        PkaTester {
            pka,
            state: Cell::new(TestState::EccWaitDoubling),
            point_doubled: Cell::new([0; 64]),
            point_mul: Cell::new([0; 64]),
            ecc_output: Cell::new([0; 64]),
            out_done: Cell::new(0),
            math_output: Cell::new([0; 32]),
            math_read_count: Cell::new(0),
            rsa_message: TakeCell::empty(),
            rsa_result: TakeCell::empty(),
        }
    }

    /// Two 32-byte 'static buffers for the RSA test, e.g. from `static_init!`.
    fn set_rsa_buffers(&self, message: &'static mut [u8], result: &'static mut [u8]) {
        self.rsa_message.replace(message);
        self.rsa_result.replace(result);
    }

    /// Registers this tester as the RSA client. Call once before `start`.
    /// (ECC and math clients are assumed to be registered by the caller, as before.)
    fn register_rsa_client(&'a self) {
        RsaCryptoBase::set_client(self.pka, self);
    }

    fn start(&self) {
        debug!("--- Starting ECC Chain ---");
        self.state.set(TestState::EccWaitDoubling);
        // Step 1: Double the generator
        self.pka.point_doubling(true).unwrap();
    }

    fn start_math_chain(&self) {
        debug!("--- Starting Math Chain ---");
        self.state.set(TestState::MathWaitAdd);
        self.math_read_count.set(0);

        self.ecc_output.set([0; 64]);
        // Step 4: Start Math Addition
        MathCryptoBase::start_computation(self.pka, 32, SupportedOp::Addition).unwrap();
    }

    fn start_verify_tests(&self) {
        debug!("--- Starting verify_point tests ---");
        // Test 1: random bytes must be rejected
        self.state.set(TestState::VerifyWaitBad);
        self.pka.verify_point().unwrap();
    }

    fn start_rsa_test(&self) {
        debug!("--- Starting RSA test ---");
        self.state.set(TestState::RsaWaitModExp);

        let message = self.rsa_message.take().expect("RSA message buffer not set");
        let result = self.rsa_result.take().expect("RSA result buffer not set");
        message.copy_from_slice(&TEST_RSA_MESSAGE);
        result.fill(0);

        if let Err((e, message, _, _, result)) = RsaCryptoBase::mod_exponent(
            self.pka,
            message,
            &TEST_MATH_MODULUS,
            &TEST_RSA_EXPONENT,
            result,
        ) {
            self.rsa_message.replace(message);
            self.rsa_result.replace(result);
            panic!("mod_exponent failed to start: {:?}", e);
        }
    }
}

impl<'a> EccClient for PkaTester<'a> {
    fn read_scalar(&self, scalar: &mut [u8]) -> Result<(), kernel::ErrorCode> {
        debug!("Read scalar");
        scalar.copy_from_slice(&TEST_ECC_SCALAR);
        Ok(())
    }

    fn read_point(&self, point: &mut [u8]) -> Result<(), kernel::ErrorCode> {
        debug!("Read point");
        match self.state.get() {
            TestState::EccWaitMul | TestState::EccWaitAdd | TestState::VerifyWaitGood => {
                // Supply the doubled point to mul, add and the verify test
                point.copy_from_slice(&self.point_doubled.get());
            }
            TestState::VerifyWaitBad => {
                point.copy_from_slice(&NOT_A_POINT);
            }
            _ => {}
        }
        Ok(())
    }

    fn read_second_point(&self, point: &mut [u8]) -> Result<(), kernel::ErrorCode> {
        debug!("Read second point");
        if self.state.get() == TestState::EccWaitAdd {
            // Supply the multiplied point as the second operand for addition
            point.copy_from_slice(&self.point_mul.get());
        }
        Ok(())
    }

    fn write_point(&self, point: &[u8]) -> Result<(), kernel::ErrorCode> {
        debug!("Wrote point");
        let mut buf = self.ecc_output.get();
        let idx = self.out_done.get();
        buf[idx..idx + point.len()].copy_from_slice(point);
        self.out_done.set(idx + point.len());
        self.ecc_output.set(buf);
        Ok(())
    }

    fn operation_done(&self, result: Result<(), kernel::ErrorCode>) {
        debug!("operation_done: {:02x?}", self.ecc_output.get());
        self.out_done.set(0);

        // verify_point tests: the result itself is what is being tested.
        match self.state.get() {
            TestState::VerifyWaitBad => {
                if result == Err(kernel::ErrorCode::INVAL) {
                    debug!("[PASS] verify_point rejects random bytes");
                } else {
                    debug!("[FAIL] verify_point on random bytes returned {:?}", result);
                    panic!("test failed: verify_point accepted a non-point");
                }
                // Test 2: the doubled point must be accepted
                self.state.set(TestState::VerifyWaitGood);
                self.pka.verify_point().unwrap();
                return;
            }
            TestState::VerifyWaitGood => {
                if result == Ok(()) {
                    debug!("[PASS] verify_point accepts the doubled point");
                } else {
                    debug!("[FAIL] verify_point on 2G returned {:?}", result);
                    panic!("test failed: verify_point rejected 2G");
                }
                self.start_rsa_test();
                return;
            }
            _ => {}
        }

        if result.is_err() {
            debug!("ECC Hardware Error");
            return;
        }

        match self.state.get() {
            TestState::EccWaitDoubling => {
                expect("point doubling (2G)", &self.ecc_output.get(), &EXPECTED_2G);
                self.point_doubled.set(self.ecc_output.get());
                self.ecc_output.set([0; 64]);
                self.state.set(TestState::EccWaitMul);
                // Step 2: Multiply the doubled point by the scalar
                self.pka.scalar_multiplication(false).unwrap();
            }
            TestState::EccWaitMul => {
                expect(
                    "scalar multiplication (3 * 2G)",
                    &self.ecc_output.get(),
                    &EXPECTED_6G,
                );
                self.point_mul.set(self.ecc_output.get());
                self.ecc_output.set([0; 64]);
                self.state.set(TestState::EccWaitAdd);
                // Step 3: Add the doubled point to the multiplied point
                self.pka.point_addition(false).unwrap();
            }
            TestState::EccWaitAdd => {
                expect(
                    "point addition (2G + 6G)",
                    &self.ecc_output.get(),
                    &EXPECTED_8G,
                );
                debug!("ECC complete addition success!");
                self.start_math_chain();
            }
            _ => {}
        }
    }
}

impl<'a> MathClient<SupportedOp> for PkaTester<'a> {
    fn read_modulus(&self, modulus: &mut [u8]) -> Result<(), kernel::ErrorCode> {
        modulus.copy_from_slice(&TEST_MATH_MODULUS);
        Ok(())
    }

    fn read_number(&self, num: &mut [u8]) {
        // Always provide the first operand here
        if self.state.get() == TestState::MathWaitMod || self.state.get() == TestState::MathWaitDiv
        {
            num.copy_from_slice(&TEST_MATH_MODULUS);
            num[31] = 0xfe;
        } else {
            num.copy_from_slice(&TEST_MATH_A);
        }
    }

    fn read_second_number(&self, num: &mut [u8]) {
        // Dedicated function for the second operand
        num.copy_from_slice(&TEST_MATH_B);
    }

    fn write_number(&self, num: &[u8]) -> Result<(), kernel::ErrorCode> {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&num[0..32]);
        self.math_output.set(buf);
        Ok(())
    }

    fn computation_completed(&self, result: Result<(), kernel::ErrorCode>) {
        debug!("computation_completed: {:02x?}", self.math_output.get());
        if result.is_err() {
            debug!("Math Hardware Error");
            return;
        }

        match self.state.get() {
            TestState::MathWaitAdd => {
                expect(
                    "modular addition (5 + 7)",
                    &self.math_output.get(),
                    &EXPECTED_MATH_ADD,
                );
                debug!("Math Addition Success!");
                self.state.set(TestState::MathWaitMul);
                // Step 5: Start Math Multiplication
                MathCryptoBase::start_computation(self.pka, 32, SupportedOp::Multiplication)
                    .unwrap();
            }
            TestState::MathWaitMul => {
                expect(
                    "modular multiplication (5 * 7)",
                    &self.math_output.get(),
                    &EXPECTED_MATH_MUL,
                );
                debug!("Math Multiplication Success!");
                self.state.set(TestState::MathWaitDiv);
                // Step 6: Start Math Division
                MathCryptoBase::start_computation(self.pka, 32, SupportedOp::Inverse).unwrap();
            }
            TestState::MathWaitDiv => {
                expect(
                    "modular inverse (5^-1)",
                    &self.math_output.get(),
                    &EXPECTED_MATH_INV,
                );
                debug!("Math Division Success!");
                self.state.set(TestState::MathWaitMod);
                // Step 7: Start Math Modulo
                MathCryptoBase::start_computation(self.pka, 32, SupportedOp::Modulus).unwrap();
            }
            TestState::MathWaitMod => {
                expect(
                    "modular reduction ((p+5) mod p)",
                    &self.math_output.get(),
                    &EXPECTED_MATH_MOD,
                );
                debug!("Math Modulo Success!");
                self.start_verify_tests();
            }
            _ => {}
        }
    }
}

impl<'a> kernel::hil::public_key_crypto::rsa_math::Client<'a> for PkaTester<'a> {
    fn mod_exponent_done(
        &self,
        status: Result<bool, kernel::ErrorCode>,
        message: &'static mut [u8],
        _modulus: &'static [u8],
        _exponent: &'static [u8],
        result: &'static mut [u8],
    ) {
        if status != Ok(true) {
            debug!("[FAIL] RSA mod_exponent returned {:?}", status);
            panic!("test failed: RSA mod_exponent");
        }
        expect(
            "RSA mod_exponent (m^0x10001 mod p)",
            result,
            &EXPECTED_RSA_RESULT,
        );

        self.rsa_message.replace(message);
        self.rsa_result.replace(result);

        self.state.set(TestState::Done);
        debug!("--- All PKA Operations Finished ---");
    }
}
struct NucleoU545RE {
    console: &'static capsules_core::console::Console<'static>,
    scheduler: &'static components::sched::round_robin::RoundRobinComponentType,
    systick: cortexm33::systick::SysTick,
    led: &'static capsules_core::led::LedDriver<
        'static,
        kernel::hil::led::LedHigh<'static, stm32u545::gpio::Pin<'static>>,
        1,
    >,
    button: &'static capsules_core::button::Button<'static, stm32u545::gpio::Pin<'static>>,
    alarm: &'static capsules_core::alarm::AlarmDriver<
        'static,
        capsules_core::virtualizers::virtual_alarm::VirtualMuxAlarm<
            'static,
            stm32u545::tim::Tim2<'static>,
        >,
    >,
    pwm: &'static capsules_extra::pwm::Pwm<'static, 1>,
    adc: &'static capsules_core::adc::AdcVirtualized<'static>,
    dac: &'static capsules_extra::dac::Dac<'static>,
    gpio: &'static GpioDriver,
    crc: &'static capsules_extra::crc::CrcDriver<'static, stm32u545::crc::CRC<'static>>,
    hash: &'static capsules_crypto::hash::Hash<stm32u545::hash::hash::Hash<'static>>,
    hmac: &'static capsules_crypto::hmac::Hmac<stm32u545::hash::hash::Hash<'static>>,
    hkdf: &'static capsules_crypto::hkdf::Hkdf<stm32u545::hash::hash::Hash<'static>>,
    aes: &'static capsules_extra::symmetric_encryption::aes::AesDriver<
        'static,
        stm32u545::aes::ecb::Aes<'static, AES256>,
        AES256,
    >,
    spi: &'static capsules_core::spi_controller::Spi<
        'static,
        capsules_core::virtualizers::virtual_spi::VirtualSpiMasterDevice<
            'static,
            stm32u545::spi::Spi<'static>,
        >,
    >,
    i2c: &'static capsules_core::i2c_master::I2CMasterDriver<'static, stm32u545::i2c::I2c<'static>>,
    date_time:
        &'static capsules_extra::date_time::DateTimeCapsule<'static, stm32u545::rtc::Rtc<'static>>,
}

impl SyscallDriverLookup for NucleoU545RE {
    fn with_driver<F, R>(&self, driver_num: usize, f: F) -> R
    where
        F: FnOnce(Option<&dyn kernel::syscall::SyscallDriver>) -> R,
    {
        match driver_num {
            capsules_core::console::DRIVER_NUM => f(Some(self.console)),
            capsules_core::led::DRIVER_NUM => f(Some(self.led)),
            capsules_core::button::DRIVER_NUM => f(Some(self.button)),
            capsules_core::alarm::DRIVER_NUM => f(Some(self.alarm)),
            capsules_extra::pwm::DRIVER_NUM => f(Some(self.pwm)),
            capsules_core::adc::DRIVER_NUM => f(Some(self.adc)),
            capsules_extra::dac::DRIVER_NUM => f(Some(self.dac)),
            capsules_core::gpio::DRIVER_NUM => f(Some(self.gpio)),
            capsules_extra::crc::DRIVER_NUM => f(Some(self.crc)),
            capsules_crypto::hash::DRIVER_NUM => f(Some(self.hash)),
            capsules_crypto::hmac::DRIVER_NUM => f(Some(self.hmac)),
            capsules_crypto::hkdf::DRIVER_NUM => f(Some(self.hkdf)),
            capsules_extra::symmetric_encryption::aes::DRIVER_NUM => f(Some(self.aes)),
            capsules_core::spi_controller::DRIVER_NUM => f(Some(self.spi)),
            capsules_core::i2c_master::DRIVER_NUM => f(Some(self.i2c)),
            capsules_extra::date_time::DRIVER_NUM => f(Some(self.date_time)),
            _ => f(None),
        }
    }
}

impl KernelResources<ChipHw> for NucleoU545RE {
    type SyscallDriverLookup = Self;
    type SyscallFilter = ();
    type ProcessFault = ();
    type Scheduler = components::sched::round_robin::RoundRobinComponentType;
    type SchedulerTimer = cortexm33::systick::SysTick;
    type WatchDog = ();
    type ContextSwitchCallback = ();

    fn syscall_driver_lookup(&self) -> &Self::SyscallDriverLookup {
        self
    }
    fn syscall_filter(&self) -> &Self::SyscallFilter {
        &()
    }
    fn process_fault(&self) -> &Self::ProcessFault {
        &()
    }
    fn scheduler(&self) -> &Self::Scheduler {
        self.scheduler
    }
    fn scheduler_timer(&self) -> &Self::SchedulerTimer {
        &self.systick
    }
    fn watchdog(&self) -> &Self::WatchDog {
        &()
    }
    fn context_switch_callback(&self) -> &Self::ContextSwitchCallback {
        &()
    }
}

/// Helper function for board-specific pin muxing
unsafe fn set_pin_primary_functions(periphs: &stm32u545::chip::Stm32u5xxDefaultPeripherals) {
    use kernel::hil::gpio::Configure;

    // USART1 Pins (PA9/10)
    let pin9 = periphs.gpio_a.pin(PinId::Pin09);
    let pin10 = periphs.gpio_a.pin(PinId::Pin10);
    pin9.set_mode(stm32u545::gpio::Mode::AlternateFunction);
    pin9.set_alternate_function(7);
    pin9.set_speed_high();
    pin10.set_mode(stm32u545::gpio::Mode::AlternateFunction);
    pin10.set_alternate_function(7);
    pin10.set_speed_high();

    // I2C1 Pins (PB6/PB7)
    let pin_scl = periphs.gpio_b.pin(PinId::Pin06);
    let pin_sda = periphs.gpio_b.pin(PinId::Pin07);

    pin_scl.set_mode(stm32u545::gpio::Mode::AlternateFunction);
    pin_scl.set_alternate_function(4);
    pin_scl.set_open_drain();
    pin_scl.set_floating_state(kernel::hil::gpio::FloatingState::PullUp);
    pin_scl.set_speed_high();

    pin_sda.set_mode(stm32u545::gpio::Mode::AlternateFunction);
    pin_sda.set_alternate_function(4);
    pin_sda.set_open_drain();
    pin_sda.set_floating_state(kernel::hil::gpio::FloatingState::PullUp);
    pin_sda.set_speed_high();

    // Default Config
    // LED Pin (PA5)
    periphs.gpio_a.pin(PinId::Pin05).make_output();

    // SPI_CLOCK (PB3)
    let spi1_sck = periphs.gpio_b.pin(PinId::Pin03);
    spi1_sck.set_mode(stm32u545::gpio::Mode::AlternateFunction);
    spi1_sck.set_alternate_function(5);
    spi1_sck.set_speed_high();

    // SPI_MISO (PA6)
    let spi1_miso = periphs.gpio_a.pin(PinId::Pin06);
    spi1_miso.set_mode(stm32u545::gpio::Mode::AlternateFunction);
    spi1_miso.set_alternate_function(5);
    spi1_miso.set_speed_high();

    // SPI_MOSI (PA7)
    let spi1_mosi = periphs.gpio_a.pin(PinId::Pin07);
    spi1_mosi.set_mode(stm32u545::gpio::Mode::AlternateFunction);
    spi1_mosi.set_alternate_function(5);
    spi1_mosi.set_speed_high();

    // SPI1_CS (PC9)
    let spi1_cs = periphs.gpio_c.pin(PinId::Pin09);
    spi1_cs.set_mode(stm32u545::gpio::Mode::Output);
    spi1_cs.set_speed_high();

    // Button Pin (PC13) - Hardware is Active High
    let btn = periphs.gpio_c.pin(PinId::Pin13);
    btn.make_input();
    btn.set_floating_state(kernel::hil::gpio::FloatingState::PullDown);

    // Arduino A0 (PA_0 = ADC1_IN5 - Channel5)
    periphs
        .gpio_a
        .pin(PinId::Pin00)
        .set_mode(stm32u545::gpio::Mode::Analog);
    // Arduino A1 (PA_1 = ADC1_IN6 - Channel6)
    periphs
        .gpio_a
        .pin(PinId::Pin01)
        .set_mode(stm32u545::gpio::Mode::Analog);
    //DAC pin (PA4) A2 on the board
    periphs
        .gpio_a
        .pin(PinId::Pin04)
        .set_mode(stm32u545::gpio::Mode::Analog);
    // Arduino A3 (PB_0 = ADC1_IN15 - Channel15)
    periphs
        .gpio_b
        .pin(PinId::Pin00)
        .set_mode(stm32u545::gpio::Mode::Analog);
    // Arduino A4 (PC_1 = ADC1_IN2 - Channel2)
    periphs
        .gpio_c
        .pin(PinId::Pin01)
        .set_mode(stm32u545::gpio::Mode::Analog);
    // Arduino A5 (PC_0 = ADC1_IN1 - Channel1)
    periphs
        .gpio_c
        .pin(PinId::Pin00)
        .set_mode(stm32u545::gpio::Mode::Analog);
}

#[inline(never)]
#[allow(clippy::large_stack_arrays)]
unsafe fn start() -> (
    &'static kernel::Kernel,
    &'static NucleoU545RE,
    &'static ChipHw,
) {
    ChipHw::init();

    kernel::deferred_call::initialize_deferred_call_state::<
        <ChipHw as kernel::platform::chip::Chip>::ThreadIdProvider,
    >();

    // Create Individual Drivers
    let exti = static_init!(
        stm32u545::exti::Exti<'static>,
        stm32u545::exti::Exti::new(stm32u545::exti::EXTI_BASE)
    );

    let dma1 = static_init!(
        stm32u545::dma::Dma,
        stm32u545::dma::Dma::new(stm32u545::dma::DMA1_BASE)
    );

    // Load Peripherals Bundle
    let periphs = static_init!(
        stm32u545::chip::Stm32u5xxDefaultPeripherals<'static>,
        stm32u545::chip::Stm32u5xxDefaultPeripherals::new(exti, dma1)
    );

    let trng = static_init!(
        stm32u545::rng::Trng<'static>,
        stm32u545::rng::Trng::new(RNG_BASE)
    );
    trng.init();
    periphs.rcc.enable_trng();

    // Initialize DMA buffer for hash peripheral
    let hash_dma_buf = static_init!([u8; FIFO_SIZE], [0u8; FIFO_SIZE]);

    // Initialize wiring (DMA, clocks)
    periphs.init(hash_dma_buf);

    // Board specific wiring
    periphs.tim2.start();
    set_pin_primary_functions(periphs);

    // Kernel and Muxes
    let processes = components::process_array::ProcessArrayComponent::new()
        .finalize(components::process_array_component_static!(NUM_PROCS));
    let board_kernel = static_init!(kernel::Kernel, kernel::Kernel::new(processes.as_slice()));

    let uart_mux = components::console::UartMuxComponent::new(&periphs.usart1, 115200)
        .finalize(components::uart_mux_component_static!());

    let spi_mux = components::spi::SpiMuxComponent::new(&periphs.spi1)
        .finalize(components::spi_mux_component_static!(stm32u545::spi::Spi));

    let alarm_mux = components::alarm::AlarmMuxComponent::new(&periphs.tim2).finalize(
        components::alarm_mux_component_static!(stm32u545::tim::Tim2),
    );

    // Capsules
    let console = components::console::ConsoleComponent::new(
        board_kernel,
        capsules_core::console::DRIVER_NUM,
        uart_mux,
        create_capability!(capabilities::MemoryAllocationCapability),
    )
    .finalize(components::console_component_static!());

    components::debug_writer::DebugWriterComponent::new::<
        <ChipHw as kernel::platform::chip::Chip>::ThreadIdProvider,
    >(
        uart_mux,
        create_capability!(capabilities::SetDebugWriterCapability),
    )
    .finalize(components::debug_writer_component_static!());

    kernel::create_typed_capability!(process_console_cap, ProcessConsoleCap:
        kernel::capabilities::ProcessManagementCapability,
        kernel::capabilities::ProcessStartCapability
    );
    let aes_driver = components::aes::AesDriverComponent::new(
        board_kernel,
        capsules_extra::symmetric_encryption::aes::DRIVER_NUM,
        &periphs.aes,
        create_capability!(MemoryAllocationCapability),
    )
    .finalize(components::aes_driver_component_static!(
        stm32u545::aes::ecb::Aes<'static, AES256>,
        AES256
    ));

    let process_console = components::process_console::ProcessConsoleComponent::new(
        board_kernel,
        uart_mux,
        alarm_mux,
        components::process_printer::ProcessPrinterTextComponent::new()
            .finalize(components::process_printer_text_component_static!()),
        None,
        process_console_cap,
    )
    .finalize(components::process_console_component_static!(
        stm32u545::tim::Tim2,
        ProcessConsoleCap
    ));
    let _ = process_console.start();

    let alarm = components::alarm::AlarmDriverComponent::new(
        board_kernel,
        capsules_core::alarm::DRIVER_NUM,
        alarm_mux,
        create_capability!(capabilities::MemoryAllocationCapability),
    )
    .finalize(components::alarm_component_static!(stm32u545::tim::Tim2));

    let date_time = components::date_time::DateTimeComponent::new(
        board_kernel,
        capsules_extra::date_time::DRIVER_NUM,
        &periphs.rtc,
        create_capability!(capabilities::MemoryAllocationCapability),
    )
    .finalize(components::date_time_component_static!(
        stm32u545::rtc::Rtc<'static>
    ));

    let led_pin = static_init!(stm32u545::gpio::Pin, periphs.gpio_a.pin(PinId::Pin05));
    let led = components::led::LedsComponent::new().finalize(components::led_component_static!(
        kernel::hil::led::LedHigh<'static, stm32u545::gpio::Pin>,
        kernel::hil::led::LedHigh::new(led_pin)
    ));

    let spi_cs = static_init!(
        stm32u545::gpio::Pin<'static>,
        periphs.gpio_c.pin(PinId::Pin09)
    );

    spi_cs.make_output();
    spi_cs.set();

    let spi = components::spi::SpiSyscallComponent::new(
        board_kernel,
        spi_mux,
        spi_cs,
        capsules_core::spi_controller::DRIVER_NUM,
        create_capability!(capabilities::MemoryAllocationCapability),
    )
    .finalize(components::spi_syscall_component_static!(
        stm32u545::spi::Spi<'static>
    ));

    let button = components::button::ButtonComponent::new(
        board_kernel,
        capsules_core::button::DRIVER_NUM,
        components::button_component_helper!(
            stm32u545::gpio::Pin,
            (
                static_init!(stm32u545::gpio::Pin, periphs.gpio_c.pin(PinId::Pin13)),
                kernel::hil::gpio::ActivationMode::ActiveHigh,
                kernel::hil::gpio::FloatingState::PullDown
            )
        ),
        create_capability!(capabilities::MemoryAllocationCapability),
    )
    .finalize(components::button_component_static!(stm32u545::gpio::Pin));

    let pwm_pin = static_init!(stm32u545::gpio::Pin, periphs.gpio_a.pin(PinId::Pin06));

    let tim3_pwm_pin = static_init!(
        stm32u545::tim::PwmPin<'static>,
        stm32u545::tim::PwmPin::new(&periphs.tim3, pwm_pin),
    );

    let pwm = components::pwm::PwmDriverComponent::new(
        board_kernel,
        capsules_extra::pwm::DRIVER_NUM,
        create_capability!(capabilities::MemoryAllocationCapability),
    )
    .finalize(components::pwm_driver_component_helper!(tim3_pwm_pin));

    let adc_mux = components::adc::AdcMuxComponent::new(&periphs.adc1)
        .finalize(components::adc_mux_component_static!(stm32u545::adc::Adc));

    // Register the ADC channels in the same order as Arduino pins A0-A5
    let adc1_channel_5 =
        components::adc::AdcComponent::new(adc_mux, stm32u545::adc::Channel::Channel5)
            .finalize(components::adc_component_static!(stm32u545::adc::Adc));
    let adc1_channel_6 =
        components::adc::AdcComponent::new(adc_mux, stm32u545::adc::Channel::Channel6)
            .finalize(components::adc_component_static!(stm32u545::adc::Adc));
    let adc1_channel_9 =
        components::adc::AdcComponent::new(adc_mux, stm32u545::adc::Channel::Channel9)
            .finalize(components::adc_component_static!(stm32u545::adc::Adc));
    let adc1_channel_15 =
        components::adc::AdcComponent::new(adc_mux, stm32u545::adc::Channel::Channel15)
            .finalize(components::adc_component_static!(stm32u545::adc::Adc));
    let adc1_channel_2 =
        components::adc::AdcComponent::new(adc_mux, stm32u545::adc::Channel::Channel2)
            .finalize(components::adc_component_static!(stm32u545::adc::Adc));
    let adc1_channel_1 =
        components::adc::AdcComponent::new(adc_mux, stm32u545::adc::Channel::Channel1)
            .finalize(components::adc_component_static!(stm32u545::adc::Adc));

    // Applications will see 6 ADC channels available, with index 0-5 corresponding directly to Arduino pins A0-A5
    let adc_syscall = components::adc::AdcVirtualComponent::new(
        board_kernel,
        capsules_core::adc::DRIVER_NUM,
        create_capability!(capabilities::MemoryAllocationCapability),
    )
    .finalize(components::adc_syscall_component_helper!(
        adc1_channel_5,
        adc1_channel_6,
        adc1_channel_9,
        adc1_channel_15,
        adc1_channel_2,
        adc1_channel_1,
    ));

    let dac = components::dac::DacComponent::new(&periphs.dac)
        .finalize(components::dac_component_static!());

    let gpio = components::gpio::GpioComponent::new(
        board_kernel,
        capsules_core::gpio::DRIVER_NUM,
        components::gpio_component_helper_owned!(
            GpioHw,
            // Digital pins
            0 => periphs.gpio_a.pin(PinId::Pin03), // D0
            1 => periphs.gpio_a.pin(PinId::Pin02), // D1
            2 => periphs.gpio_c.pin(PinId::Pin08), // D2
            // D3-D6 require GPIOB
            7 => periphs.gpio_a.pin(PinId::Pin08), // D7
            8 => periphs.gpio_c.pin(PinId::Pin07), // D8
            9 => periphs.gpio_c.pin(PinId::Pin06), // D9
            10 => periphs.gpio_c.pin(PinId::Pin09), // D10
            11 => periphs.gpio_a.pin(PinId::Pin07), // D11
            // 12 => D12/PA6 is used by the PWM capsule
            // 13 => D13/PA5 is used by the LD2 LED capsule
            // D14-D15 require GPIOB

            // Analog pins exposed as GPIO
            16 => periphs.gpio_a.pin(PinId::Pin00), // A0
            17 => periphs.gpio_a.pin(PinId::Pin01), // A1
            18 => periphs.gpio_a.pin(PinId::Pin04), // A2
            // 19 => A3 requires GPIOB
            20 => periphs.gpio_c.pin(PinId::Pin01), // A4
            21 => periphs.gpio_c.pin(PinId::Pin00), // A5

            // ST Morpho-only GPIO pins (no D/A aliases)
            22 => periphs.gpio_c.pin(PinId::Pin10), // CN7 pin 1
            23 => periphs.gpio_c.pin(PinId::Pin11), // CN7 pin 2
            24 => periphs.gpio_c.pin(PinId::Pin12), // CN7 pin 3
            25 => periphs.gpio_a.pin(PinId::Pin15), // CN7 pin 17
            26 => periphs.gpio_c.pin(PinId::Pin03), // CN7 pin 37
        ),
        create_capability!(capabilities::MemoryAllocationCapability),
    )
    .finalize(components::gpio_component_static!(GpioHw));

    // Mutex for the hashing peripheral
    let hash_mutex = components::driver_mutex::DriverMutexComponent::new(&periphs.hash).finalize(
        components::driver_mutex_component_static!(stm32u545::hash::hash::Hash<'static>, 3),
    );

    // Hash capsule
    let hash = components::crypto::hash::HashComponent::new(
        board_kernel,
        capsules_crypto::hash::DRIVER_NUM,
        hash_mutex,
        create_capability!(capabilities::MemoryAllocationCapability),
    )
    .finalize(components::hash_crypto_component_static!(
        stm32u545::hash::hash::Hash<'static>,
    ));

    // Register hashing capsule into the mutex
    if hash.register().is_err() {
        panic!("Failed to register hash capsule into the mutex");
    }

    // HMAC capsule
    let hmac = components::crypto::hmac::HmacComponent::new(
        board_kernel,
        capsules_crypto::hmac::DRIVER_NUM,
        hash_mutex,
        create_capability!(capabilities::MemoryAllocationCapability),
    )
    .finalize(components::hmac_crypto_component_static!(
        stm32u545::hash::hash::Hash<'static>,
    ));

    // Register HMAC capsule into the mutex
    if hmac.register().is_err() {
        panic!("Failed to register hmac capsule into the mutex");
    }

    // HKDF
    let hkdf = components::crypto::hkdf::HkdfComponent::new(
        board_kernel,
        capsules_crypto::hkdf::DRIVER_NUM,
        hash_mutex,
        create_capability!(capabilities::MemoryAllocationCapability),
    )
    .finalize(components::hkdf_component_static!(
        stm32u545::hash::hash::Hash<'static>
    ));

    // Register HKDF capsule into the mutex
    if hkdf.register().is_err() {
        panic!("Failed to register hkdf capsule into the mutex");
    }

    let crc = components::crc::CrcComponent::new(
        board_kernel,
        capsules_extra::crc::DRIVER_NUM,
        &periphs.crc,
        create_capability!(capabilities::MemoryAllocationCapability),
    )
    .finalize(components::crc_component_static!(
        stm32u545::crc::CRC<'static>
    ));

    let test = static_init!(PkaTester<'static>, PkaTester::new(&periphs.pka));
    MathCryptoBase::set_client(&periphs.pka, test);
    EccCrypto::set_client(&periphs.pka, test);
    let rsa_msg = static_init!([u8; 32], [0; 32]);
    let rsa_res = static_init!([u8; 32], [0; 32]);
    test.set_rsa_buffers(rsa_msg, rsa_res);
    test.register_rsa_client();
    test.start();

    let i2c = components::i2c::I2CMasterDriverComponent::new(
        board_kernel,
        capsules_core::i2c_master::DRIVER_NUM,
        &periphs.i2c1,
        create_capability!(capabilities::MemoryAllocationCapability),
    )
    .finalize(components::i2c_master_driver_component_static!(
        stm32u545::i2c::I2c
    ));

    // Platform and Interrupts
    let platform = static_init!(
        NucleoU545RE,
        NucleoU545RE {
            console,
            scheduler: components::sched::round_robin::RoundRobinComponent::new(processes)
                .finalize(components::round_robin_component_static!(NUM_PROCS)),
            systick: cortexm33::systick::SysTick::new(),
            led,
            i2c,
            button,
            alarm,
            pwm,
            adc: adc_syscall,
            dac,
            gpio,
            crc,
            hash,
            hmac,
            hkdf,
            aes: aes_driver,
            spi,
            date_time,
        }
    );

    let chip = static_init!(
        stm32u545::chip::Stm32u5xx<stm32u545::chip::Stm32u5xxDefaultPeripherals>,
        stm32u545::chip::Stm32u5xx::new(periphs)
    );

    // Symbols for linker
    extern "C" {
        /// Beginning of the ROM region containing app images.
        static _sapps: u8;
        /// End of the ROM region containing app images.
        static _eapps: u8;
        /// Beginning of the RAM region for app memory.
        static mut _sappmem: u8;
        /// End of the RAM region for app memory.
        static _eappmem: u8;
    }

    // Load processes
    let app_flash = core::slice::from_raw_parts(
        core::ptr::addr_of!(_sapps),
        core::ptr::addr_of!(_eapps) as usize - core::ptr::addr_of!(_sapps) as usize,
    );

    let app_memory = core::slice::from_raw_parts_mut(
        core::ptr::addr_of_mut!(_sappmem),
        core::ptr::addr_of!(_eappmem) as usize - core::ptr::addr_of!(_sappmem) as usize,
    );

    let _ = kernel::process::load_processes(
        board_kernel,
        chip,
        app_flash,
        app_memory,
        &capsules_system::process_policies::PanicFaultPolicy {},
        &create_capability!(capabilities::ProcessManagementCapability),
    );

    (board_kernel, platform, chip)
}

#[no_mangle]
pub unsafe fn main() {
    let main_loop_capability = create_capability!(capabilities::MainLoopCapability);

    let (board_kernel, platform, chip) = start();

    // Hand over control to the Tock Kernel Loop
    board_kernel.kernel_loop::<NucleoU545RE, ChipHw, { NUM_PROCS as u8 }>(
        platform,
        chip,
        None,
        &main_loop_capability,
    );
}
