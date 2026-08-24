// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright OxidOS Automotive 2026

//! Interface for ECC Public/Private key encryption math operations

use crate::ErrorCode;
use crate::hil::crypto::elliptic_curves::ecc_constants::Curve;

/// Upcall from the `EccCryptoBase` trait.
pub trait Client<'a> {
    /// This callback is called when the mod_exponent operation is complete.
    ///
    /// The possible ErrorCodes are:
    ///    - BUSY: An operation is already on going
    ///    - INVAL: An invalid parameter was supplied
    ///    - SIZE: The size of the `result` buffer is invalid
    ///    - NOSUPPORT: The operation is not supported
    fn scalar_multiplicaiton_done(
        &'a self,
        status: Result<bool, ErrorCode>,
        scalar: &'static [u8],
        result: &'static mut [u8],
    );
}

pub trait EccCryptoBase<'a, const P_LEN: usize, T: Curve<P_LEN>> {
    /// Set the `Client` client to be called on completion.
    fn set_client(&'a self, client: &'a dyn Client<'a>);

    /// Clear any confidential data.
    fn clear_data(&self);

    /// Calculate  and store it in the
    /// `result` buffer.
    ///
    /// On completion the `scalar_multiplicaiton_done` upcall will be scheduled.
    ///
    /// The `scalar` and `result` buffers can be any length. All of the data
    /// in the buffer up to the length of the `prime` will be used. This
    /// allows callers to allocate larger buffers to support multiple
    /// ECC lengths, but only the operation length (defined by the prime)
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
    fn scalar_multiplicaiton(
        &self,
        scalar: &'static [u8],
        result: &'static mut [u8],
    ) -> Result<(), (ErrorCode, &'static mut [u8], &'static mut [u8])>;
}
