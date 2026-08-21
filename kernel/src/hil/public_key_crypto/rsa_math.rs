// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright OxidOS Automotive 2026

//! Interface for Math Operations with long numbers modulo some other number

use crate::ErrorCode;

/// Upcall from the `RsaCryptoBase` trait.
pub trait Client<'a> {
    /// This callback is called when the mod_b operation is complete.
    ///
    /// The possible ErrorCodes are:
    ///    - BUSY: An operation is already on going
    ///    - INVAL: An invalid parameter was supplied
    ///    - SIZE: The size of the `result` buffer is invalid
    ///    - NOSUPPORT: The operation is not supported
    fn operation_done(
        &'a self,
        status: Result<bool, ErrorCode>,
        a: &'static mut [u8],
        modulus: &'static [u8],
        b: &'static [u8],
        result: &'static mut [u8],
    );
}

pub trait MathCryptoBase<'a> {
    /// Set the `Client` client to be called on completion.
    fn set_client(&'a self, client: &'a dyn Client<'a>);

    /// Clear any confidential data.
    fn clear_data(&self);
}

pub trait ModExponent<'a>: MathCryptoBase<'a> {
    /// Calculate (`a` ^ `b`) % `modulus` and store it in the
    /// `result` buffer.
    ///
    /// On completion the `operation_done()` upcall will be scheduled.
    ///
    /// The length of `modulus` must be a power of 2 and determines the length
    /// of the operation.
    ///
    /// The `a` and `b` buffers can be any length. All of the data
    /// in the buffer up to the length of the `modulus` will be used. This
    /// allows callers to allocate larger buffers to support multiple
    /// number lengths, but only the operation length (defined by the modulus)
    /// will be used.
    ///
    /// The `result` buffer must be at least as large as the `modulus` buffer,
    /// otherwise Err(SIZE) will be returned.
    /// If `result` is longer then `modulus` the data will be stored in the
    /// `result` buffer from 0 to `modulue.len()`.
    ///
    /// The possible ErrorCodes are:
    ///    - BUSY: An operation is already on going
    ///    - INVAL: An invalid parameter was supplied
    ///    - SIZE: The size of the `result` buffer is invalid
    ///    - NOSUPPORT: The operation is not supported
    fn mod_exponent(
        &self,
        a: &'static mut [u8],
        modulus: &'static [u8],
        b: &'static [u8],
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
    >;
}

pub trait ModMultiplicaiton<'a>: MathCryptoBase<'a> {
    /// Calculate (`a` * `b`) % `modulus` and store it in the
    /// `result` buffer.
    ///
    /// On completion the `operation_done()` upcall will be scheduled.
    ///
    /// The length of `modulus` must be a power of 2 and determines the length
    /// of the operation.
    ///
    /// The `a` and `b` buffers can be any length. All of the data
    /// in the buffer up to the length of the `modulus` will be used. This
    /// allows callers to allocate larger buffers to support multiple
    /// number lengths, but only the operation length (defined by the modulus)
    /// will be used.
    ///
    /// The `result` buffer must be at least as large as the `modulus` buffer,
    /// otherwise Err(SIZE) will be returned.
    /// If `result` is longer then `modulus` the data will be stored in the
    /// `result` buffer from 0 to `modulue.len()`.
    ///
    /// The possible ErrorCodes are:
    ///    - BUSY: An operation is already on going
    ///    - INVAL: An invalid parameter was supplied
    ///    - SIZE: The size of the `result` buffer is invalid
    ///    - NOSUPPORT: The operation is not supported
    fn mod_multiplication(
        &self,
        a: &'static mut [u8],
        modulus: &'static [u8],
        b: &'static [u8],
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
    >;
}

pub trait ModAddition<'a>: MathCryptoBase<'a> {
    /// Calculate (`a` + `b`) % `modulus` and store it in the
    /// `result` buffer.
    ///
    /// On completion the `operation_done()` upcall will be scheduled.
    ///
    /// The length of `modulus` must be a power of 2 and determines the length
    /// of the operation.
    ///
    /// The `a` and `b` buffers can be any length. All of the data
    /// in the buffer up to the length of the `modulus` will be used. This
    /// allows callers to allocate larger buffers to support multiple
    /// number lengths, but only the operation length (defined by the modulus)
    /// will be used.
    ///
    /// The `result` buffer must be at least as large as the `modulus` buffer,
    /// otherwise Err(SIZE) will be returned.
    /// If `result` is longer then `modulus` the data will be stored in the
    /// `result` buffer from 0 to `modulue.len()`.
    ///
    /// The possible ErrorCodes are:
    ///    - BUSY: An operation is already on going
    ///    - INVAL: An invalid parameter was supplied
    ///    - SIZE: The size of the `result` buffer is invalid
    ///    - NOSUPPORT: The operation is not supported
    fn mod_addition(
        &self,
        a: &'static mut [u8],
        modulus: &'static [u8],
        b: &'static [u8],
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
    >;
}
