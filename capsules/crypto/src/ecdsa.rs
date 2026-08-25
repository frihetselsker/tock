// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright OxidOS Automotive 2026

//! ECDSA Signer for P256 signatures using Hardware Accelerators.

use core::cell::Cell;
use kernel::ErrorCode;
use kernel::debug;
use kernel::hil;
use kernel::hil::crypto::digest::Algorithm;
use kernel::hil::crypto::digest::Digest;
use kernel::hil::crypto::digest::Hmac;
use kernel::hil::crypto::elliptic_curves::ecc_constants::{Curve, NistP256Constants};
use kernel::hil::crypto::elliptic_curves::ecc_math::{Client as EccClient, EccCryptoBase};
use kernel::hil::crypto::modular_arithmetic::{
    BasicOperation, Client as MathClient, MathCryptoBase,
};
use kernel::hil::public_key_crypto::keys::SetKeyBySliceClient;
use kernel::utilities::cells::{OptionalCell, TakeCell};
#[derive(Clone, Copy, PartialEq)]
enum State {
    Idle,
    HmacDerivingK1,
    HmacDerivingV1,
    HmacDerivingK2,
    HmacDerivingV2,
    HmacGeneratingK,
    EccCalculatingR,
    MathWriteR,
    MathMulRDa,
    MathAddH,
    MathDivK,
    MathGetSignature,
    ChangingKey,
}

pub struct EcdsaP256SignatureSigner<'a, E, M, H>
where
    E: EccCryptoBase<'a>,
    M: MathCryptoBase<'a>,
    H: Digest + Hmac,
{
    // Clients
    client: OptionalCell<&'a dyn hil::public_key_crypto::signature::ClientSign<32, 64>>,
    client_key_set: OptionalCell<&'a dyn hil::public_key_crypto::keys::SetKeyBySliceClient<32>>,

    // Hardware support
    ecc_hw: &'a E,
    math_hw: &'a M,
    hmac_hw: &'a H,

    // Cryptographic storage
    signing_key: TakeCell<'static, [u8; 32]>,
    hash_storage: TakeCell<'static, [u8; 32]>,
    signature_storage: TakeCell<'static, [u8; 64]>,

    // Internal variables
    k_val: Cell<[u8; 32]>,
    v_val: Cell<[u8; 32]>,
    r_val: Cell<[u8; 32]>,
    s_val: Cell<[u8; 32]>,
    input_counter: Cell<usize>,
    output_counter: Cell<usize>,
    key_counter: Cell<usize>,

    // State and state switching
    state: Cell<State>,
    deferred_call: kernel::deferred_call::DeferredCall,
    new_key_buffer: TakeCell<'static, [u8; 32]>,
}

impl<'a, E, M, H> EcdsaP256SignatureSigner<'a, E, M, H>
where
    E: EccCryptoBase<'a>,
    M: MathCryptoBase<'a>,
    H: Digest + Hmac,
{
    pub fn new(
        signing_key: &'static mut [u8; 32],
        ecc_hw: &'a E,
        math_hw: &'a M,
        hmac_hw: &'a H,
    ) -> Self {
        Self {
            client: OptionalCell::empty(),
            client_key_set: OptionalCell::empty(),
            ecc_hw,
            math_hw,
            hmac_hw,
            signing_key: TakeCell::new(signing_key),
            hash_storage: TakeCell::empty(),
            signature_storage: TakeCell::empty(),
            k_val: Cell::new([0; 32]),
            v_val: Cell::new([0; 32]),
            r_val: Cell::new([0; 32]),
            s_val: Cell::new([0; 32]),
            input_counter: Cell::new(0),
            output_counter: Cell::new(0),
            key_counter: Cell::new(0),
            state: Cell::new(State::Idle),
            deferred_call: kernel::deferred_call::DeferredCall::new(),
            new_key_buffer: TakeCell::empty(),
        }
    }

    fn complete_signature(&self, result: Result<(), ErrorCode>) {
        self.state.set(State::Idle);
        self.ecc_hw.clear_data();
        self.math_hw.clear_data();
        self.hmac_hw.clear_data();
        self.client.map(|client| {
            if let (Some(h), Some(s)) = (self.hash_storage.take(), self.signature_storage.take()) {
                // Populate the signature buffer with [r, s]
                s[0..32].copy_from_slice(&self.r_val.get());
                s[32..64].copy_from_slice(&self.s_val.get());

                client.signing_done(result, h, s);
            }
        });
        self.k_val.set([0; 32]);
        self.v_val.set([0; 32]);
        self.r_val.set([0; 32]);
        self.s_val.set([0; 32]);
        self.input_counter.set(0);
        self.output_counter.set(0);
        self.key_counter.set(0);
    }

    fn update_var_from_buf(&self, var: &Cell<[u8; 32]>, index: usize, buf: &[u8]) -> usize {
        let mut var_buf = var.get();
        let mut counter = 0;
        buf.iter()
            .zip(var_buf.iter_mut().skip(index))
            .for_each(|(out_buf, in_buf)| {
                *in_buf = *out_buf;
                counter += 1;
            });
        var.set(var_buf);
        var_buf.fill(0);
        counter
    }

    fn read_var_to_buf(&self, var: &Cell<[u8; 32]>, index: usize, buf: &mut [u8]) -> usize {
        let mut var_buf = var.get();
        let mut counter = 0;
        buf.iter_mut()
            .zip(var_buf.iter().skip(index))
            .for_each(|(driver_byte, k_val_byte)| {
                *driver_byte = *k_val_byte;
                counter += 1;
            });
        var_buf.fill(0);
        counter
    }

    fn check_k(&self) -> bool {
        let mut k = self.k_val.get();
        let mut non_zero = false;
        let mut k_less_than_n = false;
        let mut exactly_equal_so_far = true;

        k.iter()
            .zip(NistP256Constants::N.iter())
            .for_each(|(&key_byte, &order_byte)| {
                let key_byte_non_null = key_byte != 0;
                non_zero |= key_byte_non_null;
                let byte_less = key_byte < order_byte;
                let byte_equal = key_byte == order_byte;
                k_less_than_n |= byte_less & exactly_equal_so_far;
                exactly_equal_so_far &= byte_equal;
            });
        k.fill(0);
        k_less_than_n & non_zero
    }
}

impl<'a, E, M, H> hil::public_key_crypto::signature::SignatureSign<'a, 32, 64>
    for EcdsaP256SignatureSigner<'a, E, M, H>
where
    E: EccCryptoBase<'a>,
    M: MathCryptoBase<'a>,
    H: Digest + Hmac,
{
    fn set_sign_client(
        &self,
        client: &'a dyn hil::public_key_crypto::signature::ClientSign<32, 64>,
    ) {
        self.client.replace(client);
    }

    fn sign(
        &self,
        hash: &'static mut [u8; 32],
        signature: &'static mut [u8; 64],
    ) -> Result<(), (ErrorCode, &'static mut [u8; 32], &'static mut [u8; 64])> {
        if self.state.get() != State::Idle || self.signing_key.is_none() {
            return Err((ErrorCode::BUSY, hash, signature));
        }
        // RFC 6979 step b: Set V to 0x01...01
        self.v_val.set([0x01; 32]);
        // RFC 6979 step c: Set K to 0x00...00
        self.k_val.set([0x00; 32]);

        self.state.set(State::HmacDerivingK1);
        self.input_counter.set(0);
        self.output_counter.set(0);
        self.key_counter.set(0);

        if let Err(e) = self.hmac_hw.authenticate(Algorithm::Sha256, 97, 32) {
            return Err((e, hash, signature));
        }
        self.hash_storage.replace(hash);
        self.signature_storage.replace(signature);

        Ok(())
    }
}

impl<'a, E, M, H> kernel::hil::crypto::digest::Client for EcdsaP256SignatureSigner<'a, E, M, H>
where
    E: EccCryptoBase<'a>,
    M: MathCryptoBase<'a>,
    H: Digest + Hmac,
{
    fn read_input(&self, input: &mut [u8]) -> Result<usize, ErrorCode> {
        let state = self.state.get();
        let index = self.input_counter.get();

        match state {
            State::HmacDerivingK2 | State::HmacDerivingK1 => {
                // K1: HMAC_K(V || 0x00 || d_a || hash) (97 bytes for P256)
                // K2: HMAC_K(V || 0x01 || d_a || hash) (97 bytes for P256)
                let mut v = self.v_val.get();
                let single_byte = if matches!(state, State::HmacDerivingK1) {
                    0x00
                } else {
                    0x01
                };
                let mut copied = 0;
                self.signing_key.map(|d_a| {
                    self.hash_storage.map(|hash| {
                        input
                            .iter_mut()
                            .zip(
                                v.iter() // V
                                    .chain([single_byte].iter()) // 0x00 or 0x01
                                    .chain(d_a.iter()) // d_a
                                    .chain(hash.iter()) // hash
                                    .skip(index), // skip over already read bytes
                            )
                            .for_each(|(input_byte, target_byte)| {
                                *input_byte = *target_byte;
                                copied += 1;
                            });
                    });
                });
                self.input_counter.set(index + copied);
                v.fill(0);
                Ok(copied)
            }
            State::HmacDerivingV1 | State::HmacDerivingV2 | State::HmacGeneratingK => {
                // Just V (32 bytes)
                let counter = self.read_var_to_buf(&self.v_val, index, input);
                self.input_counter.set(index + counter);
                Ok(counter)
            }
            _ => Err(ErrorCode::FAIL),
        }
    }

    fn write_output(&self, output: &[u8]) -> Result<(), ErrorCode> {
        let index = self.output_counter.get();
        match self.state.get() {
            State::HmacDerivingK1 | State::HmacDerivingK2 => {
                self.output_counter
                    .set(index + self.update_var_from_buf(&self.k_val, index, output));
            }
            State::HmacDerivingV1 | State::HmacDerivingV2 => {
                self.output_counter
                    .set(index + self.update_var_from_buf(&self.v_val, index, output));
            }
            State::HmacGeneratingK => {
                // The final output T becomes our ephemeral k
                self.output_counter
                    .set(index + self.update_var_from_buf(&self.k_val, index, output));
                self.update_var_from_buf(&self.v_val, index, &self.k_val.get()); // V is updated to T for the next potential loop iteration
            }
            _ => return Err(ErrorCode::FAIL),
        }
        Ok(())
    }

    fn hash_done(&self, result: Result<(), ErrorCode>) {
        self.key_counter.set(0);
        self.input_counter.set(0);
        self.output_counter.set(0);
        if result.is_err() {
            self.complete_signature(result);
            return;
        }

        match self.state.get() {
            State::HmacDerivingK1 => {
                self.state.set(State::HmacDerivingV1);
                if let Err(e) = self.hmac_hw.authenticate(Algorithm::Sha256, 32, 32) {
                    self.complete_signature(Err(e));
                    return;
                }
            }
            State::HmacDerivingV1 => {
                self.state.set(State::HmacDerivingK2);
                if let Err(e) = self.hmac_hw.authenticate(Algorithm::Sha256, 97, 32) {
                    self.complete_signature(Err(e));
                    return;
                }
            }
            State::HmacDerivingK2 => {
                self.state.set(State::HmacDerivingV2);
                if let Err(e) = self.hmac_hw.authenticate(Algorithm::Sha256, 32, 32) {
                    self.complete_signature(Err(e));
                    return;
                }
            }
            State::HmacDerivingV2 => {
                self.state.set(State::HmacGeneratingK);
                if let Err(e) = self.hmac_hw.authenticate(Algorithm::Sha256, 32, 32) {
                    self.complete_signature(Err(e));
                    return;
                }
            }
            State::HmacGeneratingK => {
                if self.check_k() {
                    debug!("{:02x?}", self.k_val.get());
                    // Move to ECC Math: Calculate R = k * G
                    self.state.set(State::EccCalculatingR);
                    if let Err(e) = self
                        .ecc_hw
                        .scalar_multiplication::<32, NistP256Constants>(true)
                    {
                        self.complete_signature(Err(e));
                        return;
                    }
                } else {
                    panic!("NOOOOOOOOO");
                }
            }
            _ => {
                self.complete_signature(Err(ErrorCode::FAIL));
            }
        }
    }
}

impl<'a, E, M, H> kernel::hil::crypto::digest::HmacClient for EcdsaP256SignatureSigner<'a, E, M, H>
where
    E: EccCryptoBase<'a>,
    M: MathCryptoBase<'a>,
    H: Digest + Hmac,
{
    fn read_key(&self, key: &mut [u8]) -> Result<usize, ErrorCode> {
        let index = self.key_counter.get();
        let counter = self.read_var_to_buf(&self.k_val, index, key);
        self.key_counter.set(counter + index);
        Ok(counter)
    }
}

impl<'a, E, M, H> EccClient<'a> for EcdsaP256SignatureSigner<'a, E, M, H>
where
    E: EccCryptoBase<'a>,
    M: MathCryptoBase<'a>,
    H: Digest + Hmac,
{
    fn read_scalar(&self, scalar: &mut [u8]) -> Result<(), ErrorCode> {
        if self.state.get() == State::EccCalculatingR {
            let index = self.input_counter.get();
            let counter = self.read_var_to_buf(&self.k_val, index, scalar);
            self.input_counter.set(index + counter);
            Ok(())
        } else {
            Err(ErrorCode::FAIL)
        }
    }

    fn read_point(&self, _point: &mut [u8]) -> Result<(), ErrorCode> {
        Err(ErrorCode::INVAL)
    }

    fn read_second_point(&self, _point: &mut [u8]) -> Result<(), ErrorCode> {
        Err(ErrorCode::INVAL)
    }

    fn write_point(&self, point: &[u8]) -> Result<(), ErrorCode> {
        if self.state.get() == State::EccCalculatingR {
            let index = self.output_counter.get();
            let counter = self.update_var_from_buf(&self.r_val, index, point);
            self.output_counter.set(index + counter);
            Ok(())
        } else {
            Err(ErrorCode::FAIL)
        }
    }

    fn operation_done(&self, result: Result<(), ErrorCode>) {
        self.input_counter.set(0);
        self.output_counter.set(0);
        if result.is_err() {
            self.complete_signature(result);
            return;
        }

        self.state.set(State::MathWriteR);
        if let Err(e) = self.math_hw.start_operation(32) {
            self.complete_signature(Err(e));
        }
    }
}

impl<'a, E, M, H> MathClient<'a> for EcdsaP256SignatureSigner<'a, E, M, H>
where
    E: EccCryptoBase<'a>,
    M: MathCryptoBase<'a>,
    H: Digest + Hmac,
{
    fn read_modulus(&self, modulus: &mut [u8]) -> Result<(), ErrorCode> {
        let index = self.key_counter.get();
        let end_index = (index + modulus.len()).min(32);
        modulus.copy_from_slice(&NistP256Constants::N[index..end_index]);
        self.key_counter.set(end_index);
        Ok(())
    }

    fn read_number(&self, num: &mut [u8]) -> Result<(), ErrorCode> {
        let index = self.input_counter.get();
        match self.state.get() {
            State::MathWriteR => {
                let counter = self.read_var_to_buf(&self.r_val, index, num);
                self.input_counter.set(counter + index);
            }
            State::MathMulRDa => {
                self.signing_key.map(|key| {
                    let mut counter = 0;
                    key.iter().skip(index).zip(num.iter_mut()).for_each(
                        |(key_byte, driver_byte)| {
                            *driver_byte = *key_byte;
                            counter += 1;
                        },
                    );
                    self.input_counter.set(counter + index);
                });
            }
            State::MathAddH => {
                self.hash_storage.map(|hash| {
                    let mut counter = 0;
                    hash.iter().skip(index).zip(num.iter_mut()).for_each(
                        |(hash_byte, driver_byte)| {
                            *driver_byte = *hash_byte;
                            counter += 1;
                        },
                    );
                    self.input_counter.set(counter + index);
                });
            }
            State::MathDivK => {
                let counter = self.read_var_to_buf(&self.k_val, index, num);
                self.input_counter.set(counter + index);
            }
            _ => {}
        }
        Ok(())
    }

    fn write_output(&self, output: &[u8]) -> Result<(), ErrorCode> {
        let index = self.output_counter.get();
        let counter = self.update_var_from_buf(&self.s_val, index, output);
        self.output_counter.set(index + counter);
        Ok(())
    }

    fn computation_done(&self, result: Result<(), ErrorCode>) -> BasicOperation {
        if result.is_err() {
            panic!();
        }
        self.input_counter.set(0);
        match self.state.get() {
            State::MathWriteR => {
                self.state.set(State::MathMulRDa);
                BasicOperation::Multiplication
            }
            State::MathMulRDa => {
                self.state.set(State::MathAddH);
                BasicOperation::Addition
            }
            State::MathAddH => {
                self.state.set(State::MathDivK);
                BasicOperation::Division
            }
            State::MathDivK => {
                self.state.set(State::MathGetSignature);
                BasicOperation::GetOutput
            }
            _ => BasicOperation::GetOutput,
        }
    }

    fn operation_done(&self, result: Result<(), ErrorCode>) {
        self.complete_signature(result);
    }
}

impl<'a, E, M, H> hil::public_key_crypto::keys::SetKeyBySlice<'a, 32>
    for EcdsaP256SignatureSigner<'a, E, M, H>
where
    E: EccCryptoBase<'a>,
    M: MathCryptoBase<'a>,
    H: Digest + Hmac,
{
    fn set_key(
        &self,
        key: &'static mut [u8; 32],
    ) -> Result<(), (ErrorCode, &'static mut [u8; 32])> {
        if !matches!(self.state.get(), State::Idle) {
            return Err((ErrorCode::BUSY, key));
        }
        self.state.set(State::ChangingKey);
        self.new_key_buffer.replace(key);
        self.deferred_call.set();
        Ok(())
    }

    fn set_client(&self, client: &'a dyn SetKeyBySliceClient<32>) {
        self.client_key_set.replace(client);
    }
}

impl<'a, E, M, H> kernel::deferred_call::DeferredCallClient
    for EcdsaP256SignatureSigner<'a, E, M, H>
where
    E: EccCryptoBase<'a>,
    M: MathCryptoBase<'a>,
    H: Digest + Hmac,
{
    fn handle_deferred_call(&self) {
        match self.state.get() {
            State::MathGetSignature => {
                self.complete_signature(Ok(()));
            }
            State::ChangingKey => {
                self.new_key_buffer.take().map(|key| {
                    self.signing_key.map(|skey| {
                        skey.copy_from_slice(key);
                    });
                    self.client_key_set.map(|client| {
                        client.set_key_done(key, Ok(()));
                    });
                });
                self.state.set(State::Idle);
            }
            _ => {}
        }
    }

    fn register(&'static self) {
        self.deferred_call.register(self);
    }
}
