// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! Interfaces for message digest algorithms.
//!
//! This module separates the digest operation from the algorithm used to perform it. Algorithm
//! marker types provide the digest length and fixed-size output type, while [`Digest`] and
//! [`DigestClient`] define the asynchronous data flow shared by digest implementations.

use core::marker::PhantomData;

use crate::{ErrorCode, capabilities::DigestDriverCapability, hil::crypto::context::Session};

/// Properties of a message digest algorithm.
pub trait DigestAlgorithm {
    /// Fixed-size byte array containing a digest produced by this algorithm.
    ///
    /// The byte length of this type must equal [`Self::DIGEST_LEN`].
    type Output: AsRef<[u8]> + AsMut<[u8]> + ?Sized;

    type Params;
}
macro_rules! digest_algorithm {
    // Fixed-size output
    ($name:ident, $digest_len:expr, $block_len:expr) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name;

        impl $name {
            pub const DIGEST_LEN: usize = $digest_len;
        }

        impl DigestAlgorithm for $name {
            type Output = [u8; $digest_len];
            type Params = ();
        }

        impl HmacAlgorithm for $name {
            const BLOCK_LEN: usize = $block_len;
        }
    };
    // Variable output
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name;

        impl DigestAlgorithm for $name {
            type Output = [u8];
            type Params = usize;
        }
    };
}

digest_algorithm!(Md5, 16, 512 >> 3);
digest_algorithm!(Sha1, 20, 512 >> 3);
digest_algorithm!(Sha224, 28, 512 >> 3);
digest_algorithm!(Sha256, 32, 512 >> 3);
digest_algorithm!(Sha384, 48, 1024 >> 3);
digest_algorithm!(Sha512, 64, 1024 >> 3);
digest_algorithm!(Sha3_224, 28, 1152 >> 3);
digest_algorithm!(Sha3_256, 32, 1088 >> 3);
digest_algorithm!(Sha3_384, 48, 832 >> 3);
digest_algorithm!(Sha3_512, 64, 576 >> 3);
digest_algorithm!(Shake128);
digest_algorithm!(Shake256);
digest_algorithm!(Sm3, 32, 512 >> 3);

/// Right to start an operation
pub struct Idle;
/// Right to change the state of the operation
pub struct Active<A: DigestAlgorithm>(Idle, PhantomData<A>);

impl Idle {
    pub fn activate<A: DigestAlgorithm>(self, _cap: &dyn DigestDriverCapability) -> Active<A> {
        Active(self, PhantomData)
    }
}

impl<A: DigestAlgorithm> Active<A> {
    pub fn deactivate(self, _cap: &dyn DigestDriverCapability) -> Idle {
        self.0
    }
}

pub enum DigestRequest<A: DigestAlgorithm> {
    OneShot {
        token: Idle,
        params: A::Params,
        len: usize,
    },
    Begin {
        token: Idle,
        params: A::Params,
        len: usize,
    },
    Update {
        token: Active<A>,
        len: usize,
        is_last: bool,
    },
    Abort {
        token: Active<A>,
    },
}

pub enum Next<A: DigestAlgorithm> {
    Continue(Active<A>),
    Done(Idle),
}

pub struct DigestSession<A>(PhantomData<A>);
impl<A: DigestAlgorithm> Session for DigestSession<A> {
    type IdleToken = Idle;
    type ActiveToken = Active<A>;
}

/// Computes a message digest using algorithm `A`.
pub trait Digest<A: DigestAlgorithm> {
    /// Initiate a digest operation over `len` bytes of input.
    ///
    /// Input is retrieved through [`DigestClient::read_input`]. The computed digest is returned
    /// through [`DigestClient::write_digest`], followed by exactly one
    /// [`DigestClient::digest_done`] callback. Callbacks must not occur before this method returns.
    ///
    /// Returns [`ErrorCode::BUSY`] if an operation is already in progress, [`ErrorCode::RESERVE`]
    /// if no client is registered, or [`ErrorCode::SIZE`] if `len` exceeds an implementation
    /// limit known when this method is called. On `Ok(())`, a
    /// completion callback will occur. On `Err`, no callbacks will occur for this request.
    fn digest(&self, req: DigestRequest<A>) -> Result<(), ErrorCode>;

    /// Set the client that will receive callbacks for digest operations.
    fn set_client(&self, client: &'static dyn DigestClient<A>);
}

/// Client callbacks for [`Digest`] operations.
pub trait DigestClient<A: DigestAlgorithm> {
    /// Retrieve input to hash.
    ///
    /// The client must write input into `input` and return the number of bytes written. A driver
    /// may issue this callback multiple times, but each destination must fit within the remaining
    /// input. The total number of bytes consumed must equal the `len` passed to [`Digest::digest`].
    /// Follow the [crypto data movement contract](super#callback-oriented-data-movement):
    /// return between one byte and `input.len()` bytes for each nonempty request. A zero or
    /// oversized count terminates the operation with [`ErrorCode::SIZE`]. Empty messages do
    /// not cause input callbacks.
    fn read_input(&self, input: &mut [u8]) -> Result<usize, ErrorCode>;

    /// Return the computed digest.
    ///
    /// The driver must call this exactly once with the digest of all input bytes before signaling
    /// successful completion.
    fn write_digest(&self, digest: &A::Output) -> Result<(), ErrorCode>;

    /// Signal completion of a digest operation.
    ///
    /// This callback occurs exactly once after a request accepted by [`Digest::digest`]. If a data
    /// callback returns an error, the driver must immediately abort the operation and report that
    /// error through `result`.
    fn digest_done(&self, result: Result<Next<A>, (ErrorCode, Idle)>);
}

pub trait HmacAlgorithm: DigestAlgorithm<Params = ()> {
    const BLOCK_LEN: usize;
}

pub struct HmacSession<A>(PhantomData<A>);
impl<A: HmacAlgorithm> Session for HmacSession<A> {
    type IdleToken = Idle;
    type ActiveToken = Active<A>;
}

pub enum HmacRequest<A: HmacAlgorithm> {
    OneShot {
        token: Idle,
        key_len: usize,
        len: usize,
    },
    Begin {
        token: Idle,
        key_len: usize,
        len: usize,
    },
    Update {
        token: Active<A>,
        len: usize,
        is_last: bool,
    },
    Abort {
        token: Active<A>,
    },
}

pub trait Hmac<A: HmacAlgorithm>: Digest<A> {
    fn authenticate(&self, req: HmacRequest<A>) -> Result<(), ErrorCode>;

    fn set_client(&self, client: &'static dyn HmacClient<A>);
}

pub trait HmacClient<A: HmacAlgorithm>: DigestClient<A> {
    fn read_key(&self, key: &mut [u8]) -> Result<usize, ErrorCode>;
}
