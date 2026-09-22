// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright OxidOS Automotive 2026.

use core::cell::Cell;

use kernel::hil::crypto::elliptic_curves::ecc_constants::{Curve, NistP256Constants, P_256_P_SIZE};
use kernel::hil::crypto::elliptic_curves::ecc_math::{EccClient, EccCrypto, VerifyEccPoint};
use kernel::hil::crypto::modular_arithmetic::{MathClient, MathCryptoBase};
use kernel::hil::public_key_crypto::rsa_math::{Client, RsaCryptoBase};
use kernel::utilities::StaticRef;
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable, Writeable};
use kernel::{ErrorCode, debug};

use crate::pkc::constants::{
    ADD_CURVE_MODULUS_IDX, ADD_P_X_IDX, ADD_P_Y_IDX, ADD_P_Z_IDX, ADD_Q_X_IDX, ADD_Q_Y_IDX,
    ADD_Q_Z_IDX, ADD_RESULT_X_IDX, ADD_RESULT_Y_IDX, ARITH_OP_A_IDX, CLRFR, CR, CURVE_A_IDX,
    CURVE_A_SIGN_IDX, CURVE_B_IDX, CURVE_MODULUS_IDX, CURVE_MODULUS_LEN_IDX, ERR_CHECK_IDX,
    EXP_IDX, EXP_LEN_IDX, K_IDX, MATH_RESULT_IDX, MOD_VALUE_IDX, MONTGOMERY_R2_IDX, OP_A_IDX,
    OP_LEN_IDX, PKA_BASE, PRIME_ORDER_IDX, PRIME_ORDER_LEN_IDX, PkaRegisters, R2_MOD_P, RESULT_IDX,
    RESULT_X_IDX, RESULT_Y_IDX, SR, SupportedOp, X_IDX, Y_IDX,
};

#[derive(Copy, Clone, Debug, PartialEq)]
enum State {
    Idle,
    Rsa,
    ScalarMul,
    PointAddition,
    ProjToAffinePass1,
    ProjToAffinePass2,
    ProjToAffinePass3,
    VerifyPoint,
    MathAddition,
    MathDivisionInvert,
    MathComputeR2,
    MathComputeAR,
    MathComputeAB,
}

pub struct Pka<'a> {
    registers: StaticRef<PkaRegisters>,

    rsa_client: OptionalCell<&'a dyn Client<'a>>,
    ecc_client: OptionalCell<&'a dyn EccClient>,
    math_client: OptionalCell<&'a dyn MathClient<SupportedOp>>,

    modulus: OptionalCell<&'static [u8]>,
    exponent: OptionalCell<&'static [u8]>,

    message: TakeCell<'static, [u8]>,
    result: TakeCell<'static, [u8]>,

    math_len: Cell<usize>,

    state: Cell<State>,
}

impl<'a> Pka<'a> {
    pub const fn new() -> Pka<'a> {
        Pka {
            registers: PKA_BASE,

            rsa_client: OptionalCell::empty(),
            ecc_client: OptionalCell::empty(),
            math_client: OptionalCell::empty(),

            modulus: OptionalCell::empty(),
            exponent: OptionalCell::empty(),

            message: TakeCell::empty(),
            result: TakeCell::empty(),

            math_len: Cell::new(0),

            state: Cell::new(State::Idle),
        }
    }

    fn write_slice(&self, idx: usize, data: &[u8]) {
        let chunks = data.rchunks(4);
        for (i, chunk) in chunks.enumerate() {
            if let Some(ram_cell) = self.registers.ram.get(idx + i) {
                let mut slice = [0u8; 4];
                let offset = 4 - chunk.len();
                slice[offset..].copy_from_slice(chunk);
                let semi_word = u32::from_be_bytes(slice);
                ram_cell.set(semi_word);
            } else {
                break;
            }
        }
    }

    fn read_slice(&self, idx: usize, buffer: &mut [u8]) {
        let chunks = buffer.rchunks_mut(4);
        for (i, chunk) in chunks.enumerate() {
            if let Some(ram_cell) = self.registers.ram.get(idx + i) {
                let semi_word = ram_cell.get();
                let bytes = semi_word.to_be_bytes();
                let offset = 4 - chunk.len();
                chunk.copy_from_slice(&bytes[offset..])
            } else {
                break;
            }
        }
    }

    fn enable_peripheral(&self) -> Result<(), ErrorCode> {
        if self.registers.sr.is_set(SR::BUSY) {
            return Err(ErrorCode::BUSY);
        }
        self.registers.cr.modify(CR::EN::SET);
        while !self.registers.sr.is_set(SR::INITOK) {}
        Ok(())
    }

    fn load_p256_parameters(&self) {
        self.registers.ram[PRIME_ORDER_LEN_IDX].set((P_256_P_SIZE as u32) << 3);
        self.registers.ram[PRIME_ORDER_LEN_IDX + 1].set(0);
        self.registers.ram[CURVE_MODULUS_LEN_IDX].set((P_256_P_SIZE as u32) << 3);
        self.registers.ram[CURVE_MODULUS_LEN_IDX + 1].set(0);
        self.registers.ram[CURVE_A_SIGN_IDX].set(0);
        self.registers.ram[CURVE_A_SIGN_IDX + 1].set(0);

        self.write_slice(CURVE_A_IDX, &NistP256Constants::EQ_PARAMS.0);
        self.write_slice(CURVE_B_IDX, &NistP256Constants::EQ_PARAMS.1);
        self.write_slice(PRIME_ORDER_IDX, &NistP256Constants::N);
        self.write_slice(MONTGOMERY_R2_IDX, &R2_MOD_P);
        self.write_slice(CURVE_MODULUS_IDX, &NistP256Constants::P);
        self.write_slice(ADD_CURVE_MODULUS_IDX, &NistP256Constants::P);
    }

    fn start_operation(&self, mode: kernel::utilities::registers::FieldValue<u32, CR::Register>) {
        self.registers.cr.modify(
            mode + CR::PROCENDIE::SET
                + CR::ADDERRIE::SET
                + CR::RAMERRIE::SET
                + CR::OPERRIE::SET
                + CR::EN::SET,
        );
        self.registers.cr.modify(CR::START::SET);
    }

    fn start_projective_to_affine(&self) {
        self.start_operation(CR::MODE::ECCProjectiveToAffine);
    }

    fn feed_affine_to_projective(&self) -> ([u8; P_256_P_SIZE], [u8; P_256_P_SIZE]) {
        let mut x = [0u8; P_256_P_SIZE];
        let mut y = [0u8; P_256_P_SIZE];

        self.read_slice(RESULT_X_IDX, &mut x);
        self.read_slice(RESULT_Y_IDX, &mut y);
        self.write_slice(ADD_RESULT_X_IDX, &x);
        self.write_slice(ADD_RESULT_Y_IDX, &y);

        (x, y)
    }

    pub fn handle_interrupt(&self) {
        if self.registers.sr.is_set(SR::OPERRF) {
            self.registers.clrfr.write(CLRFR::OPERRFC::SET);
        }
        if self.registers.sr.is_set(SR::ADDRERRF) {
            self.registers.clrfr.write(CLRFR::ADDERRFC::SET);
        }
        if self.registers.sr.is_set(SR::RAMERRF) {
            self.registers.clrfr.write(CLRFR::RAMERRFC::SET);
        }

        let success = if self.registers.sr.is_set(SR::PROCENDF) {
            self.registers.clrfr.write(CLRFR::PROCENDFC::SET);
            true
        } else {
            false
        };

        debug!("interrupt gotten in state: {:?}", self.state.get());
        match self.state.get() {
            State::Idle => {}
            State::Rsa => {
                let modulus = self.modulus.take().unwrap();
                let exponent = self.exponent.take().unwrap();
                let message = self.message.take().unwrap();
                let result = self.result.take().unwrap();
                self.state.set(State::Idle);

                if success {
                    self.read_slice(RESULT_IDX, result);
                    self.rsa_client.map(|client| {
                        client.mod_exponent_done(Ok(true), message, modulus, exponent, result)
                    });
                } else {
                    self.rsa_client.map(|client| {
                        client.mod_exponent_done(
                            Err(ErrorCode::FAIL),
                            message,
                            modulus,
                            exponent,
                            result,
                        );
                    });
                }
            }
            State::ScalarMul => {
                let mut errs = [0u8; 8];
                self.read_slice(ERR_CHECK_IDX, &mut errs);
                debug!(
                    "le: {:08x?}, be: {:08x?}",
                    u64::from_le_bytes(errs),
                    u64::from_be_bytes(errs),
                );
                let mut res = [0u8; 2 * P_256_P_SIZE];
                self.read_slice(RESULT_X_IDX, &mut res[0..P_256_P_SIZE]);
                self.read_slice(RESULT_Y_IDX, &mut res[P_256_P_SIZE..]);
                self.state.set(State::Idle);
                self.ecc_client.map(|client| {
                    let _ = client.write_point(&res);
                    client.operation_done(Ok(()));
                });
            }
            State::PointAddition => {
                if success {
                    self.state.set(State::ProjToAffinePass1);
                    self.start_projective_to_affine();
                } else {
                    self.state.set(State::Idle);
                    self.ecc_client
                        .map(|client| client.operation_done(Err(ErrorCode::FAIL)));
                }
            }
            State::ProjToAffinePass1 => {
                self.state.set(State::ProjToAffinePass2);
                self.feed_affine_to_projective();
                self.start_projective_to_affine();
            }
            State::ProjToAffinePass2 => {
                self.state.set(State::ProjToAffinePass3);
                let (x_out, _) = self.feed_affine_to_projective();
                self.ecc_client.map(|client| client.write_point(&x_out));
                self.start_projective_to_affine();
            }
            State::ProjToAffinePass3 => {
                self.state.set(State::Idle);
                let mut y_out = [0u8; P_256_P_SIZE];
                self.read_slice(RESULT_Y_IDX, &mut y_out);
                self.ecc_client.map(|client| {
                    let _ = client.write_point(&y_out);
                    client.operation_done(Ok(()));
                });
            }
            State::VerifyPoint => {
                self.state.set(State::Idle);
                if let Some(ram_cell) = self.registers.ram.get(ADD_P_Y_IDX) {
                    let result_code = ram_cell.get();
                    let result = if result_code == 0xD60D {
                        Ok(())
                    } else {
                        Err(ErrorCode::INVAL)
                    };
                    self.ecc_client.map(|client| client.operation_done(result));
                }
            }
            State::MathAddition => {
                self.state.set(State::Idle);
                if success {
                    let len = self.math_len.get();
                    let mut buf = [0u8; 512];
                    let buf_slice = &mut buf[0..len];

                    self.read_slice(MATH_RESULT_IDX, buf_slice);

                    self.math_client.map(|client| {
                        let _ = client.write_number(buf_slice);
                        client.computation_completed(Ok(()));
                    });
                } else {
                    self.math_client
                        .map(|client| client.computation_completed(Err(ErrorCode::FAIL)));
                }
            }
            State::MathDivisionInvert => {
                if success {
                    let len = self.math_len.get();
                    let mut buf = [0u8; 512];
                    let buf_slice = &mut buf[0..len];

                    // Result of inversion is B^-1. Save it to EXP_IDX temporarily.
                    self.read_slice(MATH_RESULT_IDX, buf_slice);
                    self.write_slice(EXP_IDX, buf_slice);

                    self.state.set(State::MathComputeR2);

                    // Modulus length and value are already prepared at RAM@0x408 and RAM@0x1088 respectively[cite: 2].
                    // Trigger Montgomery parameter computation with MODE[5:0] set to 0x01[cite: 2].
                    self.start_operation(CR::MODE::MontgomeryOnly);
                } else {
                    self.state.set(State::Idle);
                    self.math_client
                        .map(|client| client.computation_completed(Err(ErrorCode::FAIL)));
                }
            }
            State::MathComputeR2 => {
                if success {
                    let len = self.math_len.get();
                    let mut buf = [0u8; 512];
                    let buf_slice = &mut buf[0..len];

                    // Read the resulting Montgomery parameter (R^2 mod n) from RAM@0x620[cite: 2].
                    self.read_slice(MATH_RESULT_IDX, buf_slice);
                    self.write_slice(ARITH_OP_A_IDX, buf_slice);

                    // Compute AR = A * r2modn mod n. The output is in the Montgomery domain[cite: 1].
                    self.state.set(State::MathComputeAR);
                    self.start_operation(CR::MODE::MontgomeryMultiplication);
                } else {
                    self.state.set(State::Idle);
                    self.math_client
                        .map(|client| client.computation_completed(Err(ErrorCode::FAIL)));
                }
            }
            State::MathComputeAR => {
                if success {
                    let len = self.math_len.get();
                    let mut buf = [0u8; 512];
                    let buf_slice = &mut buf[0..len];

                    self.read_slice(MATH_RESULT_IDX, buf_slice);
                    self.write_slice(OP_A_IDX, buf_slice);

                    // Retrieve B (or B^-1 for division) saved in EXP_IDX and place in ARITH_OP_A_IDX
                    self.read_slice(EXP_IDX, buf_slice);
                    self.write_slice(ARITH_OP_A_IDX, buf_slice);

                    // Compute AB = AR * B mod n. The output is in the natural domain[cite: 1].
                    self.state.set(State::MathComputeAB);
                    self.start_operation(CR::MODE::MontgomeryMultiplication);
                } else {
                    self.state.set(State::Idle);
                    self.math_client
                        .map(|client| client.computation_completed(Err(ErrorCode::FAIL)));
                }
            }
            State::MathComputeAB => {
                self.state.set(State::Idle);
                if success {
                    let len = self.math_len.get();
                    let mut buf = [0u8; 512];
                    let buf_slice = &mut buf[0..len];

                    self.read_slice(MATH_RESULT_IDX, buf_slice);

                    self.math_client.map(|client| {
                        let _ = client.write_number(buf_slice);
                        client.computation_completed(Ok(()));
                    });
                } else {
                    self.math_client
                        .map(|client| client.computation_completed(Err(ErrorCode::FAIL)));
                }
            }
        }
    }
}

fn get_bitlen(data: &[u8]) -> u32 {
    for (i, &byte) in data.iter().enumerate() {
        if byte != 0 {
            let bits = 8 - byte.leading_zeros();
            let remained = (data.len() - 1 - i) as u32;
            return bits + remained * 8;
        }
    }
    0
}

impl<'a> RsaCryptoBase<'a> for Pka<'a> {
    fn set_client(&'a self, client: &'a dyn Client<'a>) {
        self.rsa_client.set(client);
    }

    fn clear_data(&self) {
        for i in 0..self.registers.ram.len() {
            self.registers.ram[i].set(0);
        }
    }

    fn mod_exponent(
        &self,
        message: &'static mut [u8],
        modulus: &'static [u8],
        exponent: &'static [u8],
        result: &'static mut [u8],
    ) -> Result<
        (),
        (
            ErrorCode,
            &'static mut [u8],
            &'static [u8],
            &'static [u8],
            &'static mut [u8],
        ),
    > {
        if self.registers.sr.is_set(SR::BUSY) || self.state.get() != State::Idle {
            return Err((ErrorCode::BUSY, message, modulus, exponent, result));
        }

        if result.len() < modulus.len() || exponent.is_empty() || message.is_empty() {
            return Err((ErrorCode::SIZE, message, modulus, exponent, result));
        }

        let exp_bits = get_bitlen(exponent);
        let op_bits = get_bitlen(modulus);

        if exp_bits == 0 || op_bits == 0 {
            return Err((ErrorCode::INVAL, message, modulus, exponent, result));
        }

        self.registers.cr.modify(CR::EN::SET);
        while !self.registers.sr.is_set(SR::INITOK) {}

        self.state.set(State::Rsa);

        RsaCryptoBase::clear_data(self);

        self.registers.ram[EXP_LEN_IDX].set(exp_bits);
        self.registers.ram[EXP_LEN_IDX + 1].set(0);
        self.registers.ram[OP_LEN_IDX].set(op_bits);
        self.registers.ram[OP_LEN_IDX + 1].set(0);

        self.write_slice(EXP_IDX, exponent);
        self.write_slice(MOD_VALUE_IDX, modulus);
        self.write_slice(OP_A_IDX, message);

        self.message.replace(message);
        self.modulus.set(modulus);
        self.exponent.set(exponent);
        self.result.replace(result);

        self.start_operation(CR::MODE::MontgomeryModularExp);

        Ok(())
    }
}

impl<'a> EccCrypto<'a, P_256_P_SIZE, NistP256Constants> for Pka<'a> {
    fn set_client(
        &self,
        client: &'a dyn kernel::hil::crypto::elliptic_curves::ecc_math::EccClient,
    ) {
        self.ecc_client.replace(client);
    }

    fn clear_data(&self) {
        for i in 0..self.registers.ram.len() {
            self.registers.ram[i].set(0);
        }
    }

    fn point_doubling(&self, use_curve_generator: bool) -> Result<(), ErrorCode> {
        self.enable_peripheral()?;
        self.state.set(State::ScalarMul);
        self.load_p256_parameters();

        let mut scalar = [0u8; P_256_P_SIZE];
        scalar[P_256_P_SIZE - 1] = 2;
        self.write_slice(K_IDX, &scalar);

        if !use_curve_generator {
            let mut point = [0u8; 2 * P_256_P_SIZE];
            self.ecc_client.map(|client| client.read_point(&mut point));
            self.write_slice(X_IDX, &point[0..P_256_P_SIZE]);
            self.write_slice(Y_IDX, &point[P_256_P_SIZE..]);
        } else {
            self.write_slice(X_IDX, &NistP256Constants::GENERATOR.0);
            self.write_slice(Y_IDX, &NistP256Constants::GENERATOR.1);
        }

        self.start_operation(CR::MODE::MontgomeryECC);
        Ok(())
    }

    fn point_addition(&self, use_curve_generator: bool) -> Result<(), ErrorCode> {
        self.enable_peripheral()?;
        self.state.set(State::PointAddition);
        self.load_p256_parameters();

        let mut z_coord = [0u8; P_256_P_SIZE];
        z_coord[P_256_P_SIZE - 1] = 1;

        if !use_curve_generator {
            let mut point = [0u8; 2 * P_256_P_SIZE];
            self.ecc_client.map(|client| client.read_point(&mut point));
            self.write_slice(ADD_P_X_IDX, &point[0..P_256_P_SIZE]);
            self.write_slice(ADD_P_Y_IDX, &point[P_256_P_SIZE..]);
        } else {
            self.write_slice(ADD_P_X_IDX, &NistP256Constants::GENERATOR.0);
            self.write_slice(ADD_P_Y_IDX, &NistP256Constants::GENERATOR.1);
        }
        self.write_slice(ADD_P_Z_IDX, &z_coord);

        let mut point_q = [0u8; 2 * P_256_P_SIZE];
        self.ecc_client
            .map(|client| client.read_second_point(&mut point_q));
        self.write_slice(ADD_Q_X_IDX, &point_q[0..P_256_P_SIZE]);
        self.write_slice(ADD_Q_Y_IDX, &point_q[P_256_P_SIZE..]);
        self.write_slice(ADD_Q_Z_IDX, &z_coord);

        self.start_operation(CR::MODE::ECCCompleteAddition);
        Ok(())
    }

    fn scalar_multiplication(&self, use_curve_generator: bool) -> Result<(), ErrorCode> {
        self.enable_peripheral()?;
        self.state.set(State::ScalarMul);
        self.load_p256_parameters();

        let mut scalar = [0u8; P_256_P_SIZE];
        self.ecc_client
            .map(|client| client.read_scalar(&mut scalar));
        self.write_slice(K_IDX, &scalar);

        if !use_curve_generator {
            let mut point = [0u8; 2 * P_256_P_SIZE];
            self.ecc_client.map(|client| client.read_point(&mut point));
            self.write_slice(X_IDX, &point[0..P_256_P_SIZE]);
            self.write_slice(Y_IDX, &point[P_256_P_SIZE..]);
        } else {
            self.write_slice(X_IDX, &NistP256Constants::GENERATOR.0);
            self.write_slice(Y_IDX, &NistP256Constants::GENERATOR.1);
        }

        self.start_operation(CR::MODE::MontgomeryECC);
        Ok(())
    }
}

impl<'a> VerifyEccPoint<'a, P_256_P_SIZE, NistP256Constants> for Pka<'a> {
    fn verify_point(&self) -> Result<(), ErrorCode> {
        self.enable_peripheral()?;
        self.state.set(State::VerifyPoint);
        self.load_p256_parameters();

        let mut point = [0u8; 2 * P_256_P_SIZE];
        self.ecc_client.map(|client| client.read_point(&mut point));

        self.write_slice(X_IDX, &point[0..P_256_P_SIZE]);
        self.write_slice(RESULT_Y_IDX, &point[P_256_P_SIZE..]);

        self.start_operation(CR::MODE::FpCheck);
        Ok(())
    }
}

impl<'a> MathCryptoBase<'a, SupportedOp> for Pka<'a> {
    fn set_client(&self, client: &'a dyn MathClient<SupportedOp>) {
        self.math_client.replace(client);
    }

    fn start_computation(
        &self,
        modulus_len: usize,
        operation: SupportedOp,
    ) -> Result<(), ErrorCode> {
        self.enable_peripheral()?;

        match operation {
            SupportedOp::Addition => {
                self.state.set(State::MathAddition);
                self.math_len.set(modulus_len);

                self.registers.ram[OP_LEN_IDX].set((modulus_len as u32) * 8);
                self.registers.ram[OP_LEN_IDX + 1].set(0);

                let mut buf = [0u8; 512];
                let buf_slice = &mut buf[0..modulus_len];

                self.math_client.map(|client| {
                    let _ = client.read_modulus(buf_slice);
                });
                self.write_slice(MOD_VALUE_IDX, buf_slice);

                buf_slice.fill(0);
                self.math_client.map(|client| client.read_number(buf_slice));
                self.write_slice(ARITH_OP_A_IDX, buf_slice);

                buf_slice.fill(0);
                self.math_client.map(|client| client.read_number(buf_slice));
                self.write_slice(OP_A_IDX, buf_slice);

                self.start_operation(CR::MODE::ModularAddition);
                Ok(())
            }
            SupportedOp::Multiplication => {
                self.state.set(State::MathComputeR2);
                self.math_len.set(modulus_len);

                // Set the modulus length in bits at RAM@0x408[cite: 2].
                self.registers.ram[OP_LEN_IDX].set((modulus_len as u32) * 8);
                self.registers.ram[OP_LEN_IDX + 1].set(0);

                let mut buf = [0u8; 512];
                let buf_slice = &mut buf[0..modulus_len];

                // Set the odd modulus value n at RAM@0x1088[cite: 2].
                self.math_client.map(|client| {
                    let _ = client.read_modulus(buf_slice);
                });
                self.write_slice(MOD_VALUE_IDX, buf_slice);

                buf_slice.fill(0);
                self.math_client.map(|client| client.read_number(buf_slice));
                self.write_slice(OP_A_IDX, buf_slice);

                buf_slice.fill(0);
                self.math_client.map(|client| client.read_number(buf_slice));
                self.write_slice(EXP_IDX, buf_slice);

                // Trigger Montgomery parameter computation with MODE[5:0] set to 0x01[cite: 2].
                self.start_operation(CR::MODE::MontgomeryOnly);
                Ok(())
            }
            SupportedOp::Division => {
                self.state.set(State::MathDivisionInvert);
                self.math_len.set(modulus_len);

                self.registers.ram[OP_LEN_IDX].set((modulus_len as u32) * 8);
                self.registers.ram[OP_LEN_IDX + 1].set(0);

                let mut buf = [0u8; 512];
                let buf_slice = &mut buf[0..modulus_len];

                self.math_client.map(|client| {
                    let _ = client.read_modulus(buf_slice);
                });
                self.write_slice(MOD_VALUE_IDX, buf_slice);

                buf_slice.fill(0);
                self.math_client.map(|client| client.read_number(buf_slice));
                self.write_slice(OP_A_IDX, buf_slice);

                buf_slice.fill(0);
                self.math_client.map(|client| client.read_number(buf_slice));
                self.write_slice(ARITH_OP_A_IDX, buf_slice);

                self.start_operation(CR::MODE::ModularInversion);
                Ok(())
            }
        }
    }

    fn clear_data(&self) {
        for i in 0..self.registers.ram.len() {
            self.registers.ram[i].set(0);
        }
    }
}
