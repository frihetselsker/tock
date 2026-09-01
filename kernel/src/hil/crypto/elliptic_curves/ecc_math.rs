// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright OxidOS Automotive 2026
use crate::{ErrorCode, hil::crypto::elliptic_curves::ecc_constants::Curve};

pub trait EccClient<'a> {
    fn read_scalar(&self, scalar: &mut [u8]) -> Result<(), ErrorCode>;
    fn read_point(&self, point: &mut [u8]) -> Result<(), ErrorCode>;
    fn read_second_point(&self, point: &mut [u8]) -> Result<(), ErrorCode>;
    fn write_point(&self, point: &[u8]) -> Result<(), ErrorCode>;
    fn operation_done(&self, result: Result<(), ErrorCode>);
}

pub trait EccCrypto<'a, const P_SIZE: usize, C: Curve<P_SIZE>> {
    fn set_client(&'a self, client: &'a dyn EccClient<'a>);
    fn clear_data(&self);
    fn point_doubling(&self) -> Result<(), ErrorCode>;

    fn point_addition(&self) -> Result<(), ErrorCode>;

    fn scalar_multiplication(&self, use_curve_generator: bool) -> Result<(), ErrorCode>;
}