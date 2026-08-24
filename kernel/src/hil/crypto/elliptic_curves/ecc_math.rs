// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright OxidOS Automotive 2026

//! Interface for ECC Public/Private key encryption math operations

use crate::ErrorCode;
use crate::hil::crypto::elliptic_curves::ecc_constants::Curve;

/// Upcall from the `EccCryptoBase` trait.
pub trait Client<'a> {
    fn read_scalar(&self, scalar: &mut [u8]) -> Result<(), ErrorCode>;
    fn read_point(&self, point: &mut [u8]) -> Result<(), ErrorCode>;
    fn read_second_point(&self, point: &mut [u8]) -> Result<(), ErrorCode>;
    fn write_point(&self, point: &[u8]) -> Result<(), ErrorCode>;
    fn operation_done(&self, result: Result<(), ErrorCode>);
}

pub trait EccCryptoBase<'a> {
    fn set_client(&'a self, client: &'a dyn Client<'a>);

    fn clear_data(&self);

    fn point_doubling<const P_SIZE: usize, C: Curve<P_SIZE>>(&self) -> Result<(), ErrorCode>;

    fn point_addition<const P_SIZE: usize, C: Curve<P_SIZE>>(&self) -> Result<(), ErrorCode>;

    fn scalar_multiplicaiton<const P_SIZE: usize, C: Curve<P_SIZE>>(
        &self,
        use_curve_generator: bool,
    ) -> Result<(), ErrorCode>;
}
