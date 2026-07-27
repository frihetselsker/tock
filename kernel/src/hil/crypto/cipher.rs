// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! Interfaces for symmetric block ciphers.
//!
//! This module defines cipher types and mode-specific HIL traits for symmetric encryption and
//! decryption. The cipher type supplies compile-time block and key sizes, while each mode has a
//! separate HIL and client trait so implementations and clients only expose the operations and
//! callbacks relevant to that mode.

use crate::ErrorCode;

/// Properties of a symmetric block cipher.
pub trait Cipher {
    /// Block size, in bytes.
    const BLOCK_SIZE: usize;

    /// Encryption key size, in bytes.
    const KEY_SIZE: usize;
}

/// AES with 128-bit keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aes128;

impl Cipher for Aes128 {
    const BLOCK_SIZE: usize = 16;
    const KEY_SIZE: usize = 16;
}

/// AES with 256-bit keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aes256;

impl Cipher for Aes256 {
    const BLOCK_SIZE: usize = 16;
    const KEY_SIZE: usize = 32;
}

/// Encryption or decryption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

/// Authentication tag length for Counter with CBC-MAC (CCM) mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CcmTagLength {
    Tag32,
    Tag48,
    Tag64,
    Tag80,
    Tag96,
    Tag112,
    Tag128,
}

impl CcmTagLength {
    /// Return the tag length, in bytes.
    pub const fn bytes(&self) -> usize {
        match self {
            CcmTagLength::Tag32 => 4,
            CcmTagLength::Tag48 => 6,
            CcmTagLength::Tag64 => 8,
            CcmTagLength::Tag80 => 10,
            CcmTagLength::Tag96 => 12,
            CcmTagLength::Tag112 => 14,
            CcmTagLength::Tag128 => 16,
        }
    }
}

/// Counter with Cipher Block Chaining-Message Authentication Code mode.
///
/// CCM mode is specified in [NIST SP 800-38C]. CCM is only defined for block ciphers with a
/// 16-byte block size, so this trait must only be implemented for cipher types whose
/// [`Cipher::BLOCK_SIZE`] is 16.
///
/// [NIST SP 800-38C]: https://csrc.nist.gov/pubs/sp/800/38/c/upd1/final
pub trait Ccm<C: Cipher> {
    /// Initiate a CCM operation.
    ///
    /// `len` is the length of the plaintext or ciphertext, excluding the authentication tag, and
    /// `associated_data_len` is the length of the associated data. `tag_len` selects the
    /// authentication tag length.
    ///
    /// For encryption, the client provides `len` bytes of plaintext and receives `len` bytes of
    /// ciphertext followed by the authentication tag. For decryption, the client provides `len`
    /// bytes of ciphertext followed by the authentication tag and receives `len` bytes of
    /// plaintext. Associated data is authenticated but is neither encrypted nor returned.
    ///
    /// The key, nonce, associated data, and input are retrieved through [`CcmClient`] callbacks.
    /// Output is returned through [`CcmClient::write_output`], followed by exactly one
    /// [`CcmClient::crypt_done`] callback. Callbacks must not occur before this method returns.
    ///
    /// Returns [`ErrorCode::BUSY`] if an operation is already in progress or [`ErrorCode::SIZE`]
    /// if a length exceeds an implementation limit known when this method is called. On `Ok(())`,
    /// a completion callback will occur. On `Err`, no callbacks will occur for this request.
    fn crypt(
        &self,
        len: usize,
        associated_data_len: usize,
        tag_len: CcmTagLength,
        operation: Operation,
    ) -> Result<(), ErrorCode>;

    /// Set the client that will receive callbacks for CCM operations.
    fn set_client(&self, client: &'static dyn CcmClient<C>);
}

/// Client callbacks for [`Ccm`] operations.
pub trait CcmClient<C: Cipher> {
    /// Retrieve the encryption key.
    ///
    /// The driver must provide a `key` buffer of exactly
    /// [`C::KEY_SIZE`](Cipher::KEY_SIZE) bytes. The client must fill the entire buffer before
    /// returning `Ok(())`.
    fn read_key(&self, key: &mut [u8]) -> Result<(), ErrorCode>;

    /// Retrieve the nonce.
    ///
    /// The client must write the nonce into `nonce` and return the number of bytes written. The
    /// driver must provide a buffer of at least 13 bytes. The returned nonce length must be between
    /// 7 and 13 bytes, inclusive; otherwise the driver must abort the operation with
    /// [`ErrorCode::INVAL`]. If the requested payload length cannot be encoded with the returned
    /// nonce length, the driver must abort the operation with [`ErrorCode::SIZE`].
    fn read_nonce(&self, nonce: &mut [u8]) -> Result<usize, ErrorCode>;

    /// Retrieve associated data.
    ///
    /// The client must write associated data into `associated_data` and return the number of bytes
    /// written. A driver may issue this callback multiple times, but must not request more than the
    /// `associated_data_len` passed to [`Ccm::crypt`] in total.
    fn read_associated_data(&self, associated_data: &mut [u8]) -> Result<usize, ErrorCode>;

    /// Retrieve plaintext or ciphertext and its authentication tag.
    ///
    /// For encryption, the client must provide exactly the `len` bytes of plaintext specified in
    /// [`Ccm::crypt`]. For decryption, it must provide `len` bytes of ciphertext followed by the
    /// selected authentication tag. A driver may issue this callback multiple times, preserving
    /// that byte order.
    fn read_input(&self, input: &mut [u8]) -> Result<usize, ErrorCode>;

    /// Return ciphertext and its authentication tag, or authenticated plaintext.
    ///
    /// For encryption, the driver must return `len` bytes of ciphertext followed by the selected
    /// authentication tag. For decryption, it must authenticate the complete input before calling
    /// this method, then return exactly `len` bytes of plaintext. The driver must not expose any
    /// plaintext through this callback if authentication fails.
    ///
    /// A driver may issue this callback multiple times while preserving byte order.
    fn write_output(&self, output: &[u8]) -> Result<(), ErrorCode>;

    /// Signal completion of a CCM operation.
    ///
    /// This callback occurs exactly once after a request accepted by [`Ccm::crypt`]. Authentication
    /// failure is reported as [`ErrorCode::FAIL`]. If any data callback returns an error, the
    /// driver must immediately abort the operation and report that error through `result`.
    fn crypt_done(&self, result: Result<(), ErrorCode>);
}

/// Electronic Codebook mode.
///
/// ECB mode is specified in [NIST SP 800-38A], section 6.1.
///
/// **Warning:** ECB mode does not protect the confidentiality of messages except in very narrow
/// circumstances. Use with extreme caution.
///
/// [NIST SP 800-38A]: https://csrc.nist.gov/pubs/sp/800/38/a/final
pub trait Ecb<C: Cipher> {
    /// Initiate an ECB operation.
    ///
    /// `len` is the length of the plaintext or ciphertext input, in bytes, and must be a multiple
    /// of [`C::BLOCK_SIZE`](Cipher::BLOCK_SIZE). The output has the same length as the input.
    ///
    /// The key and input are retrieved through [`EcbClient::read_key`] and
    /// [`EcbClient::read_input`]. Output is returned through [`EcbClient::write_output`], followed
    /// by exactly one [`EcbClient::crypt_done`] callback. Callbacks must not occur before this
    /// method returns.
    ///
    /// Returns [`ErrorCode::BUSY`] if an operation is already in progress or
    /// [`ErrorCode::INVAL`] if `len` is not a multiple of the cipher's block size. On `Ok(())`, a
    /// completion callback will occur. On `Err`, no callbacks will occur for this request.
    fn crypt(&self, len: usize, operation: Operation) -> Result<(), ErrorCode>;

    /// Set the client that will receive callbacks for ECB operations.
    fn set_client(&self, client: &'static dyn EcbClient<C>);
}

/// Client callbacks for [`Ecb`] operations.
pub trait EcbClient<C: Cipher> {
    /// Retrieve the encryption key.
    ///
    /// The driver must provide a `key` buffer of exactly
    /// [`C::KEY_SIZE`](Cipher::KEY_SIZE) bytes. The client must fill the entire buffer before
    /// returning `Ok(())`.
    fn read_key(&self, key: &mut [u8]) -> Result<(), ErrorCode>;

    /// Retrieve plaintext or ciphertext input.
    ///
    /// The client must write input into `input` and return the number of bytes written. A driver
    /// may issue this callback multiple times, but must not request more than the `len` passed to
    /// [`Ecb::crypt`] in total.
    fn read_input(&self, input: &mut [u8]) -> Result<usize, ErrorCode>;

    /// Return ciphertext or plaintext output.
    ///
    /// A driver may issue this callback multiple times. Across all calls, it must return exactly
    /// the `len` bytes requested by [`Ecb::crypt`], in input order.
    fn write_output(&self, output: &[u8]) -> Result<(), ErrorCode>;

    /// Signal completion of an ECB operation.
    ///
    /// This callback occurs exactly once after a request accepted by [`Ecb::crypt`]. If any data
    /// callback returns an error, the driver must immediately abort the operation and report that
    /// error through `result`.
    fn crypt_done(&self, result: Result<(), ErrorCode>);
}
