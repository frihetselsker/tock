// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright OxidOS Automotive 2026

use crate::ErrorCode;

pub trait OpAddition {
    fn addition() -> Self;
}
pub trait OpSubtraction {
    fn subtraction() -> Self;
}
pub trait OpMultiplication {
    fn multiplication() -> Self;
}
pub trait OpDivision {
    fn division() -> Self;
}
pub trait OpInverse {
    fn inverse() -> Self;
}
pub trait OpModulo {
    fn modulo() -> Self;
}

/// Upcall from the `MathCryptoBase` trait.
pub trait MathClient<Op> {
    fn read_modulus(&self, modulus: &mut [u8]) -> Result<(), ErrorCode>;
    fn read_number(&self, num: &mut [u8]);
    fn write_number(&self, num: &[u8]) -> Result<(), ErrorCode>;
    fn computation_completed(&self, result: Result<(), ErrorCode>);
}

pub trait MathCryptoBase<'a, Op> {
    fn set_client(&self, client: &'a dyn MathClient<Op>);
    fn start_computation(&self, modulus_len: usize, operation: Op) -> Result<(), ErrorCode>;
    fn clear_data(&self);
}
