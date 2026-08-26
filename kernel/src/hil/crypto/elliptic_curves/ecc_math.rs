use crate::{
    ErrorCode,
    hil::crypto::elliptic_curves::ecc_constants::{EdwardsCurve, WeierstrassCurve},
};

pub trait Client<'a> {
    fn read_scalar(&self, scalar: &mut [u8]) -> Result<(), ErrorCode>;
    fn read_point(&self, point: &mut [u8]) -> Result<(), ErrorCode>;
    fn read_second_point(&self, point: &mut [u8]) -> Result<(), ErrorCode>;
    fn write_point(&self, point: &[u8]) -> Result<(), ErrorCode>;
    fn operation_done(&self, result: Result<(), ErrorCode>);
}

pub trait EccCryptoCommon<'a> {
    fn set_client(&'a self, client: &'a dyn Client<'a>);
    fn clear_data(&self);
}

/// Implemented by peripherals whose hardware performs Weierstrass-form
/// (y² = x³ + ax + b) point arithmetic — e.g. NIST P-256, P-384.
pub trait WeierstrassEccCrypto<'a> {
    fn point_doubling<const P_SIZE: usize, C: WeierstrassCurve<P_SIZE>>(
        &self,
    ) -> Result<(), ErrorCode>;

    fn point_addition<const P_SIZE: usize, C: WeierstrassCurve<P_SIZE>>(
        &self,
    ) -> Result<(), ErrorCode>;

    fn scalar_multiplication<const P_SIZE: usize, C: WeierstrassCurve<P_SIZE>>(
        &self,
        use_curve_generator: bool,
    ) -> Result<(), ErrorCode>;
}

/// Implemented by peripherals whose hardware performs twisted-Edwards-form
/// (ax² + y² = 1 + dx²y²) point arithmetic — e.g. Ed25519.
pub trait EdwardsEccCrypto<'a> {
    fn point_addition<const P_SIZE: usize, C: EdwardsCurve<P_SIZE>>(&self)
    -> Result<(), ErrorCode>;

    fn scalar_multiplication<const P_SIZE: usize, C: EdwardsCurve<P_SIZE>>(
        &self,
        use_curve_generator: bool,
    ) -> Result<(), ErrorCode>;
}
