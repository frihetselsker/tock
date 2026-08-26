// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright OxidOS Automotive 2026

//! Interface for Math Operations with long numbers modulo some other number

use crate::ErrorCode;

/// Upcall from the `MathCryptoBase` trait.
pub trait Client<'a> {
    fn read_modulus(&self, modulus: &mut [u8]) -> Result<(), ErrorCode>;
    fn read_number(&self, num: &mut [u8]) -> Result<(), ErrorCode>;
    fn write_output(&self, output: &[u8]) -> Result<(), ErrorCode>;
    fn operation_done(&self, result: Result<(), ErrorCode>);
}

pub trait MathCryptoBase<'a> {
    /// Set the `Client` client to be called on completion.
    fn set_client(&'a self, client: &'a dyn Client<'a>);
    /// Clear any confidential data.
    fn clear_data(&self);
    fn start_chain(&self, modulus_len: usize) -> Result<(), ErrorCode>;
    fn start_operation(&self) -> Result<(), ErrorCode>;
}

pub trait Addition {
    fn chain_addition(&self);
}
pub trait Subtraction {
    fn chain_subtraction(&self);
}
pub trait Multiplication {
    fn chain_multiplication(&self);
}
pub trait Division {
    fn chain_division(&self);
}
pub trait Exponentiation {
    fn chain_exponentiation(&self);
}
pub trait Inverse {
    fn chain_inverse(&self);
}
