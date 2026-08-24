// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright OxidOS Automotive 2026

//! Interface for Math Operations with long numbers modulo some other number

use crate::ErrorCode;

#[derive(Clone, Copy)]
pub enum BasicOperation {
    Addition,
    Subtraction,
    Multiplication,
    Division,
    Exponentiation,
    Inverse,
    GetOutput,
}

/// Upcall from the `MathCryptoBase` trait.
pub trait Client<'a> {
    fn read_modulus(&self, modulus: &mut [u8]) -> Result<(), ErrorCode>;
    fn read_number(&self, num: &mut [u8]) -> Result<(), ErrorCode>;
    fn write_output(&self, output: &[u8]) -> Result<bool, ErrorCode>;
    fn computation_done(&self, result: Result<(), ErrorCode>) -> BasicOperation;
    fn operation_done(&self, result: Result<(), ErrorCode>);
}

pub trait MathCryptoBase<'a> {
    /// Set the `Client` client to be called on completion.
    fn set_client(&'a self, client: &'a dyn Client<'a>);
    /// Clear any confidential data.
    fn clear_data(&self);
    fn get_valid_operations(&self) -> [(BasicOperation, bool); 8];
    fn start_operation(&self, modulus_len: usize) -> Result<(), ErrorCode>;
}
