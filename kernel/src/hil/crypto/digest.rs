use crate::{
    ErrorCode,
    hil::crypto::digest::utilities::*,
    utilities::leasable_buffer::{SubSlice, SubSliceMut},
};

pub mod utilities;

pub trait DigestAny {
    type DigestConcrete<A: Algotithm>: Digest<A>;

    fn verify_mode(&self, mode: DigestMode) -> Result<DigestMode, ErrorCode>;
    fn set_mode(&self, mode: &DigestMode, len: Option<usize>) -> Result<(), ErrorCode>;
    fn clear_data(&self);
    fn operate_algorithm<A>(&self, token: A::Token) -> Self::DigestConcrete<A>
    where
        A: Algotithm;
    fn set_client(&self, client: &dyn ClientDigestAny);
}

pub trait Digest<A: Algotithm> {
    fn add_data(
        &self,
        data: SubSlice<'static, u8>,
    ) -> Result<(), (ErrorCode, SubSlice<'static, u8>)>;
    fn add_mut_data(
        &self,
        data: SubSliceMut<'static, u8>,
    ) -> Result<(), (ErrorCode, SubSliceMut<'static, u8>)>;
    fn run(&self, digest: &'static A::Slice) -> Result<(), (ErrorCode, &'static A::Slice)>;
    fn verify(&self, compare: &'static A::Slice) -> Result<(), (ErrorCode, &'static A::Slice)>;
}

pub trait Hmac {
    fn set_key(&self, key: &[u8]) -> Result<(), (ErrorCode, &[u8])>;
}

pub trait ClientDigestAny {
    fn add_data_done(&self, result: Result<(), ErrorCode>, data: SubSlice<'static, u8>);
    fn add_mut_data_done(&self, result: Result<(), ErrorCode>, data: SubSliceMut<'static, u8>);
    fn hash_done(&self, result: Result<(), ErrorCode>, digest: &'static mut DigestSlice);
    fn verification_done(&self, result: Result<bool, ErrorCode>, compare: &'static mut DigestSlice);
}
