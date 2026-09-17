// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright OxidOS Automotive 2026.

use kernel::ErrorCode;
use kernel::hil::crypto::elliptic_curves::ecc_constants::{NistP256Constants, P_256_P_SIZE};
use kernel::hil::crypto::elliptic_curves::ecc_math::{EccClient, EccCrypto, VerifyEccPoint};
use kernel::hil::public_key_crypto::rsa_math::{Client, RsaCryptoBase};
use kernel::utilities::StaticRef;
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable, Writeable};

use crate::pkc::constants::{
    CLRFR, CR, CURVE_MODULUS_LEN_IDX, EXP_IDX, EXP_LEN_IDX, MOD_VALUE_IDX, OP_A_IDX, OP_LEN_IDX,
    PKA_BASE, PRIME_ORDER_LEN_IDX, PkaRegisters, RESULT_IDX, SR,
};

pub struct Pka<'a> {
    registers: StaticRef<PkaRegisters>,

    rsa_client: OptionalCell<&'a dyn Client<'a>>,
    ecc_client: OptionalCell<&'a dyn EccClient>,

    modulus: OptionalCell<&'static [u8]>,
    exponent: OptionalCell<&'static [u8]>,

    message: TakeCell<'static, [u8]>,
    result: TakeCell<'static, [u8]>,
}

impl<'a> Pka<'a> {
    pub const fn new() -> Pka<'a> {
        Pka {
            registers: PKA_BASE,

            rsa_client: OptionalCell::empty(),
            ecc_client: OptionalCell::empty(),

            modulus: OptionalCell::empty(),
            exponent: OptionalCell::empty(),

            message: TakeCell::empty(),
            result: TakeCell::empty(),
        }
    }

    /// Helper function to write the data to RAM
    fn write_slice(&self, idx: usize, data: &[u8]) {
        // Four u8 slices correspond to one u32
        let chunks = data.rchunks(4);

        for (i, chunk) in chunks.enumerate() {
            if let Some(ram_cell) = self.registers.ram.get(idx + i) {
                let mut slice = [0u8; 4];
                let offset = 4 - chunk.len(); // in case chunk is less then 4 bytes

                slice[offset..].copy_from_slice(chunk);

                let semi_word = u32::from_be_bytes(slice);
                ram_cell.set(semi_word);
            } else {
                // Occurs only when buffer is longer then RAM
                break;
            }
        }
    }

    /// Helper function to read data from RAM
    fn read_slice(&self, idx: usize, buffer: &mut [u8]) {
        let chunks = buffer.rchunks_mut(4);
        for (i, chunk) in chunks.enumerate() {
            if let Some(ram_cell) = self.registers.ram.get(idx + i) {
                let semi_word = ram_cell.get();
                let bytes = semi_word.to_be_bytes();
                let offset = 4 - chunk.len();
                chunk.copy_from_slice(&bytes[offset..])
            } else {
                // Occurs only when buffer is longer then RAM
                break;
            }
        }
    }

    /// Handler for interrupts fired by PKA
    pub fn handle_interrupt(&self) {
        // Operand error
        if self.registers.sr.is_set(SR::OPERRF) {
            self.registers.clrfr.write(CLRFR::OPERRFC::SET);
        }

        // Address error
        if self.registers.sr.is_set(SR::ADDRERRF) {
            self.registers.clrfr.write(CLRFR::ADDERRFC::SET);
        }

        // RAM error
        if self.registers.sr.is_set(SR::RAMERRF) {
            self.registers.clrfr.write(CLRFR::RAMERRFC::SET);
        }

        // Successful operation
        let success = if self.registers.sr.is_set(SR::PROCENDF) {
            self.registers.clrfr.write(CLRFR::PROCENDFC::SET);
            true
        } else {
            false
        };

        // Unpack the cells
        let modulus = self.modulus.take().unwrap();
        let exponent = self.exponent.take().unwrap();
        let message = self.message.take().unwrap();
        let result = self.result.take().unwrap();

        if success {
            // Only read the result if operation was successful
            self.read_slice(RESULT_IDX, result);

            self.rsa_client.map(|client| {
                client.mod_exponent_done(Ok(true), message, modulus, exponent, result)
            });
        } else {
            self.rsa_client.map(|client| {
                client.mod_exponent_done(Err(ErrorCode::FAIL), message, modulus, exponent, result);
            });
        }
    }
}

/// Helper function to compute the number of bits in the number
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
        // Zero-out all current data
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
        // Check if PKA is not busy
        if self.registers.sr.is_set(SR::BUSY) {
            return Err((ErrorCode::BUSY, message, modulus, exponent, result));
        }

        // Check if parameters are correct
        if result.len() < modulus.len() || exponent.is_empty() || message.is_empty() {
            return Err((ErrorCode::SIZE, message, modulus, exponent, result));
        }

        // Compute lengths
        let exp_bits = get_bitlen(exponent);
        let op_bits = get_bitlen(modulus);

        // Check for 0
        if exp_bits == 0 || op_bits == 0 {
            return Err((ErrorCode::INVAL, message, modulus, exponent, result));
        }

        // Enable the peripheral
        self.registers.cr.modify(CR::EN::SET);

        // Wait for initialization
        while !self.registers.sr.is_set(SR::INITOK) {}

        RsaCryptoBase::clear_data(self);

        // Write necessary data to RAM
        // Since 1 word is 64 bits, and length are u32, we need to wipe next index to form a word
        self.registers.ram[EXP_LEN_IDX].set(exp_bits);
        self.registers.ram[EXP_LEN_IDX + 1].set(0);
        self.registers.ram[OP_LEN_IDX].set(op_bits);
        self.registers.ram[OP_LEN_IDX + 1].set(0);

        self.write_slice(EXP_IDX, exponent);
        self.write_slice(MOD_VALUE_IDX, modulus);
        self.write_slice(OP_A_IDX, message);

        // Put the values into cells
        self.message.replace(message);
        self.modulus.set(modulus);
        self.exponent.set(exponent);
        self.result.replace(result);

        // Configure the peripheral
        self.registers.cr.modify(
            CR::MODE::MontgomeryModularExp
                + CR::PROCENDIE::SET
                + CR::ADDERRIE::SET
                + CR::RAMERRIE::SET
                + CR::OPERRIE::SET
                + CR::EN::SET,
        );

        // Start the math
        self.registers.cr.modify(CR::START::SET);

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
        // Zero-out all current data
        for i in 0..self.registers.ram.len() {
            self.registers.ram[i].set(0);
        }
    }

    fn point_doubling(&self, use_curve_generator: bool) -> Result<(), ErrorCode> {
        // Check if PKA is not busy
        if self.registers.sr.is_set(SR::BUSY) {
            return Err(ErrorCode::BUSY);
        }
        Ok(())
    }

    fn point_addition(&self, use_curve_generator: bool) -> Result<(), ErrorCode> {
        // Check if PKA is not busy
        if self.registers.sr.is_set(SR::BUSY) {
            return Err(ErrorCode::BUSY);
        }
        Ok(())
    }

    fn scalar_multiplication(&self, use_curve_generator: bool) -> Result<(), ErrorCode> {
        // Check if PKA is not busy
        if self.registers.sr.is_set(SR::BUSY) {
            return Err(ErrorCode::BUSY);
        }
        // Enable the peripheral
        self.registers.cr.modify(CR::EN::SET);
        // Write necessary data to RAM
        // Since 1 word is 64 bits, and length are u32, we need to wipe next index to form a word
        self.registers.ram[PRIME_ORDER_LEN_IDX].set((P_256_P_SIZE as u32) << 3);
        self.registers.ram[PRIME_ORDER_LEN_IDX + 1].set(0);
        self.registers.ram[CURVE_MODULUS_LEN_IDX].set((P_256_P_SIZE as u32) << 3);
        self.registers.ram[CURVE_MODULUS_LEN_IDX + 1].set(0);

        // Configure the peripheral
        self.registers.cr.modify(
            CR::MODE::MontgomeryECC
                + CR::PROCENDIE::SET
                + CR::ADDERRIE::SET
                + CR::RAMERRIE::SET
                + CR::OPERRIE::SET
                + CR::EN::SET,
        );
        Ok(())
    }
}

impl<'a> VerifyEccPoint<'a, P_256_P_SIZE, NistP256Constants> for Pka<'a> {
    fn verify_point() -> Result<(), ErrorCode> {
        todo!()
    }
}
