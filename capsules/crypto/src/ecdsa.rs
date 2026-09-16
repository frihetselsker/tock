// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright OxidOS Automotive 2026

//! ECDSA Signer for P256 signatures using Hardware Accelerators.

use capsules_core::driver_mutex::DriverMutex;
use capsules_core::driver_mutex::DriverMutexClient;
use capsules_core::driver_mutex::DriverMutexHandle;
use capsules_core::driver_mutex::DriverMutexRef;
use core::cell::Cell;
use core::marker::PhantomData;
use kernel::ErrorCode;
use kernel::hil;
use kernel::hil::crypto::digest::Algorithm;
use kernel::hil::crypto::digest::Hmac;
use kernel::hil::crypto::elliptic_curves::ecc_constants::{Curve, NistP256Constants};
use kernel::hil::crypto::elliptic_curves::ecc_math::{EccClient, EccCrypto};
use kernel::hil::crypto::modular_arithmetic::OpAddition;
use kernel::hil::crypto::modular_arithmetic::OpDivision;
use kernel::hil::crypto::modular_arithmetic::OpModulo;
use kernel::hil::crypto::modular_arithmetic::OpMultiplication;
use kernel::hil::crypto::modular_arithmetic::{MathClient, MathCryptoBase};
use kernel::hil::public_key_crypto::keys::SetKeyBySliceClient;
use kernel::hil::public_key_crypto::signature::ClientSign;
use kernel::utilities::cells::MapCell;
use kernel::utilities::cells::{OptionalCell, TakeCell};

const P_LEN: usize = NistP256Constants::N.len();

#[derive(Clone, Copy, PartialEq)]
enum Operand {
    First,
    Second,
}

#[derive(Clone, Copy, PartialEq)]
enum State {
    Idle,
    ModHash,
    HmacDerivingK1,
    HmacDerivingV1,
    HmacDerivingK2,
    HmacDerivingV2,
    HmacGeneratingK,
    HmacGetNewK,
    EccCalculatingR,
    InvalidR,
    MathRDaMul(Operand),
    MathResHAdd(Operand),
    MathResKDiv(Operand),
    ChangingKey,
}

pub struct EcdsaP256SignatureSigner<'a, E, Op, M, H>
where
    E: EccCrypto<'a, 32, NistP256Constants> + 'static,
    Op: OpAddition + OpMultiplication + OpDivision + OpModulo,
    M: MathCryptoBase<'a, Op> + 'static,
    H: Hmac + 'static,
{
    // Clients
    client: OptionalCell<&'a dyn ClientSign<P_LEN, 64>>,
    client_key_set: OptionalCell<&'a dyn SetKeyBySliceClient<32>>,

    // Hardware support
    ecc_mutex: &'a DriverMutex<E>,
    ecc: MapCell<DriverMutexRef<E>>,
    ecc_handle: OptionalCell<DriverMutexHandle>,
    math_mutex: &'a DriverMutex<M>,
    math: MapCell<DriverMutexRef<M>>,
    math_handle: OptionalCell<DriverMutexHandle>,
    hmac_mutex: &'a DriverMutex<H>,
    hmac: MapCell<DriverMutexRef<H>>,
    hmac_handle: OptionalCell<DriverMutexHandle>,

    // Cryptographic storage
    signing_key: TakeCell<'static, [u8; P_LEN]>,
    hash_storage: TakeCell<'static, [u8; P_LEN]>,
    signature_storage: TakeCell<'static, [u8; 64]>,

    // Internal variables
    k_val: Cell<[u8; 32]>,
    v_val: Cell<[u8; 32]>,
    r_val: Cell<[u8; 32]>,
    s_val: Cell<[u8; 32]>,
    t_val: Cell<[u8; 32]>,
    input_counter: Cell<usize>,
    output_counter: Cell<usize>,
    key_counter: Cell<usize>,

    // State and state switching
    state: Cell<State>,
    deferred_call: kernel::deferred_call::DeferredCall,
    new_key_buffer: TakeCell<'static, [u8; 32]>,
    _phantom: PhantomData<Op>,
}

impl<'a, E, Op, M, H> EcdsaP256SignatureSigner<'a, E, Op, M, H>
where
    E: EccCrypto<'a, 32, NistP256Constants>,
    Op: OpAddition + OpMultiplication + OpDivision + OpModulo,
    M: MathCryptoBase<'a, Op>,
    H: Hmac,
{
    pub fn new(
        signing_key: &'static mut [u8; P_LEN],
        ecc_mutex: &'a DriverMutex<E>,
        math_mutex: &'a DriverMutex<M>,
        hmac_mutex: &'a DriverMutex<H>,
    ) -> Self {
        Self {
            client: OptionalCell::empty(),
            client_key_set: OptionalCell::empty(),
            ecc_mutex,
            ecc: MapCell::empty(),
            ecc_handle: OptionalCell::empty(),
            math_mutex,
            math: MapCell::empty(),
            math_handle: OptionalCell::empty(),
            hmac_mutex,
            hmac: MapCell::empty(),
            hmac_handle: OptionalCell::empty(),
            signing_key: TakeCell::new(signing_key),
            hash_storage: TakeCell::empty(),
            signature_storage: TakeCell::empty(),
            k_val: Cell::new([0; 32]),
            v_val: Cell::new([0; 32]),
            r_val: Cell::new([0; 32]),
            s_val: Cell::new([0; 32]),
            t_val: Cell::new([0; 32]),
            input_counter: Cell::new(0),
            output_counter: Cell::new(0),
            key_counter: Cell::new(0),
            state: Cell::new(State::Idle),
            deferred_call: kernel::deferred_call::DeferredCall::new(),
            new_key_buffer: TakeCell::empty(),
            _phantom: PhantomData::<Op>,
        }
    }

    pub fn register_hmac(&'static self) -> Result<(), ErrorCode> {
        if self.hmac_handle.is_some() {
            return Err(ErrorCode::ALREADY);
        }

        let hmac_handle = self.hmac_mutex.add_client(self).ok_or(ErrorCode::NOMEM)?;
        self.hmac_handle.set(hmac_handle);
        Ok(())
    }

    pub fn register_ecc(&'static self) -> Result<(), ErrorCode> {
        if self.ecc_handle.is_some() {
            return Err(ErrorCode::ALREADY);
        }

        let ecc_handle = self.ecc_mutex.add_client(self).ok_or(ErrorCode::NOMEM)?;
        self.ecc_handle.set(ecc_handle);
        Ok(())
    }

    pub fn register_math(&'static self) -> Result<(), ErrorCode> {
        if self.math_handle.is_some() {
            return Err(ErrorCode::ALREADY);
        }

        let math_handle = self.math_mutex.add_client(self).ok_or(ErrorCode::NOMEM)?;
        self.math_handle.set(math_handle);
        Ok(())
    }

    fn request_hmac(&self, size: usize) {
        self.hmac
            .map(|hmac| hmac.authenticate(Algorithm::Sha256, size, 32));
    }

    fn complete_signature(&self, result: Result<(), ErrorCode>) {
        self.state.set(State::Idle);
        self.ecc.take();
        self.math.take();
        self.hmac.take();
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
        self.t_val.set([0; 32]);
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

    fn check_t(&self) -> bool {
        let mut t = self.t_val.get();
        let mut non_zero = false;
        let mut t_less_than_n = false;
        let mut exactly_equal_so_far = true;

        t.iter()
            .zip(NistP256Constants::N.iter())
            .for_each(|(&key_byte, &order_byte)| {
                let key_byte_non_null = key_byte != 0;
                non_zero |= key_byte_non_null;
                let byte_less = key_byte < order_byte;
                let byte_equal = key_byte == order_byte;
                t_less_than_n |= byte_less & exactly_equal_so_far;
                exactly_equal_so_far &= byte_equal;
            });
        t.fill(0);
        t_less_than_n & non_zero
    }

    fn check_r(&self) -> bool {
        let mut r = self.r_val.get();
        let mut non_zero = false;

        r.iter().for_each(|&r_byte| {
            let key_byte_non_null = r_byte != 0;
            non_zero |= key_byte_non_null;
        });
        r.fill(0);
        non_zero
    }
}

impl<'a, E, Op, M, H> hil::public_key_crypto::signature::SignatureSign<'a, P_LEN, 64>
    for EcdsaP256SignatureSigner<'a, E, Op, M, H>
where
    E: EccCrypto<'a, 32, NistP256Constants>,
    Op: OpAddition + OpMultiplication + OpDivision + OpModulo,
    M: MathCryptoBase<'a, Op>,
    H: Hmac,
{
    fn set_sign_client(
        &self,
        client: &'a dyn hil::public_key_crypto::signature::ClientSign<P_LEN, 64>,
    ) {
        self.client.replace(client);
    }

    fn sign(
        &self,
        hash: &'static mut [u8; P_LEN],
        signature: &'static mut [u8; 64],
    ) -> Result<(), (ErrorCode, &'static mut [u8; P_LEN], &'static mut [u8; 64])> {
        if self.state.get() != State::Idle || self.signing_key.is_none() {
            return Err((ErrorCode::BUSY, hash, signature));
        }
        // RFC 6979 step b: Set V to 0x01...01
        self.v_val.set([0x01; 32]);
        // RFC 6979 step c: Set K to 0x00...00
        self.k_val.set([0x00; 32]);

        // clear counters
        self.input_counter.set(0);
        self.output_counter.set(0);
        self.key_counter.set(0);

        if *hash < NistP256Constants::N {
            self.state.set(State::HmacDerivingK1);
            self.hmac_handle
                .map(|handle| self.hmac_mutex.request(handle));
        } else {
            // if hash is bigger than the group order, we need to take modulo of it
            // this is part of the bits2octets
            self.math_handle
                .map(|handle| self.math_mutex.request(handle));
            self.state.set(State::ModHash);
        }
        self.hash_storage.replace(hash);
        self.signature_storage.replace(signature);
        Ok(())
    }
}

impl<'a, E, Op, M, H> DriverMutexClient for EcdsaP256SignatureSigner<'a, E, Op, M, H>
where
    E: EccCrypto<'a, 32, NistP256Constants>,
    Op: OpAddition + OpMultiplication + OpDivision + OpModulo,
    M: MathCryptoBase<'a, Op>,
    H: Hmac,
{
    fn ready(&'static self, resource: capsules_core::driver_mutex::DriverMutexAny) {
        match self.state.get() {
            State::HmacDerivingK1 => {
                match resource.downcast::<H>() {
                    Ok(hmac) => {
                        hmac.set_hmac_client(self);
                        self.hmac.put(hmac);
                        //  K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
                        self.request_hmac(32 + 1 + P_LEN + P_LEN);
                    }
                    Err(_) => return,
                };
            }
            State::ModHash => {
                match resource.downcast::<M>() {
                    Ok(math) => {
                        math.set_client(self);
                        self.math.put(math);
                        self.math
                            .map(|math| math.start_computation(P_LEN, OpModulo::modulo()))
                    }
                    Err(_) => return,
                };
            }
            State::InvalidR => {
                match resource.downcast::<H>() {
                    Ok(hmac) => {
                        hmac.set_hmac_client(self);
                        self.hmac.put(hmac);
                        self.state.set(State::HmacGetNewK);
                        self.request_hmac(33);
                    }
                    Err(_) => return,
                };
            }
            State::EccCalculatingR => {
                match resource.downcast::<E>() {
                    Ok(ecc) => {
                        ecc.set_client(self);
                        self.ecc.put(ecc);
                        self.ecc.map(|ecc| ecc.scalar_multiplication(true))
                    }
                    Err(_) => return,
                };
            }
            State::MathRDaMul(_) => {
                match resource.downcast::<M>() {
                    Ok(math) => {
                        math.set_client(self);
                        self.math.put(math);
                        self.math.map(|math| {
                            math.start_computation(P_LEN, OpMultiplication::multiplication())
                        })
                    }
                    Err(_) => return,
                };
            }
            _ => {}
        }
    }
}

impl<'a, E, Op, M, H> kernel::hil::crypto::digest::Client
    for EcdsaP256SignatureSigner<'a, E, Op, M, H>
where
    E: EccCrypto<'a, 32, NistP256Constants>,
    Op: OpAddition + OpMultiplication + OpDivision + OpModulo,
    M: MathCryptoBase<'a, Op>,
    H: Hmac,
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
            State::HmacGetNewK => {
                let mut counter = self.read_var_to_buf(&self.v_val, index, input);
                if index + counter == 32 && counter < input.len() {
                    input[counter] = 0;
                    counter += 1;
                }
                self.input_counter.set(index + counter);
                Ok(counter)
            }
            _ => Err(ErrorCode::FAIL),
        }
    }

    fn write_output(&self, output: &[u8]) -> Result<(), ErrorCode> {
        let index = self.output_counter.get();
        match self.state.get() {
            State::HmacDerivingK1 | State::HmacDerivingK2 | State::HmacGetNewK => {
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
                    .set(index + self.update_var_from_buf(&self.t_val, index, output));
                let mut t_copy = self.t_val.get();
                self.update_var_from_buf(&self.v_val, index, &t_copy); // V is updated to T for the next potential loop iteration
                t_copy.fill(0);
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
                self.request_hmac(32);
                self.state.set(State::HmacDerivingV1);
            }
            State::HmacDerivingV1 => {
                self.request_hmac(32 + 1 + P_LEN * 2);
                self.state.set(State::HmacDerivingK2);
            }
            State::HmacDerivingK2 => {
                self.request_hmac(32);
                self.state.set(State::HmacDerivingV2);
            }
            State::HmacDerivingV2 => {
                self.request_hmac(32);
                self.state.set(State::HmacGeneratingK);
            }
            State::HmacGeneratingK => {
                if self.check_t() {
                    let mut temp_t = self.t_val.get();
                    self.k_val.set(temp_t);
                    temp_t.fill(0);
                    self.hmac.take();
                    // Move to ECC Math: Calculate R = k * G
                    self.state.set(State::EccCalculatingR);
                    self.ecc_handle.map(|handle| self.ecc_mutex.request(handle));
                } else {
                    self.request_hmac(33);
                    self.state.set(State::HmacGetNewK);
                }
            }
            State::HmacGetNewK => {
                self.request_hmac(32);
                self.state.set(State::HmacDerivingV2);
            }
            _ => {
                self.complete_signature(Err(ErrorCode::FAIL));
            }
        }
    }
}

impl<'a, E, Op, M, H> kernel::hil::crypto::digest::HmacClient
    for EcdsaP256SignatureSigner<'a, E, Op, M, H>
where
    E: EccCrypto<'a, 32, NistP256Constants>,
    Op: OpAddition + OpMultiplication + OpDivision + OpModulo,
    M: MathCryptoBase<'a, Op>,
    H: Hmac,
{
    fn read_key(&self, key: &mut [u8]) -> Result<usize, ErrorCode> {
        let index = self.key_counter.get();
        let counter = self.read_var_to_buf(&self.k_val, index, key);
        self.key_counter.set(counter + index);
        Ok(counter)
    }
}

impl<'a, E, Op, M, H> EccClient for EcdsaP256SignatureSigner<'a, E, Op, M, H>
where
    E: EccCrypto<'a, 32, NistP256Constants>,
    Op: OpAddition + OpMultiplication + OpDivision + OpModulo,
    M: MathCryptoBase<'a, Op>,
    H: Hmac,
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
        self.ecc.take();
        self.input_counter.set(0);
        self.output_counter.set(0);
        if result.is_err() {
            self.complete_signature(result);
            return;
        }

        if !self.check_r() {
            self.state.set(State::InvalidR);
            self.hmac_handle
                .map(|handle| self.hmac_mutex.request(handle));
            return;
        }

        self.state.set(State::MathRDaMul(Operand::First));
        //  (a * b + c ) / d
        self.math_handle
            .map(|handle| self.math_mutex.request(handle));
    }
}

impl<'a, E, Op, M, H> MathClient<Op> for EcdsaP256SignatureSigner<'a, E, Op, M, H>
where
    E: EccCrypto<'a, 32, NistP256Constants>,
    Op: OpAddition + OpMultiplication + OpDivision + OpModulo,
    M: MathCryptoBase<'a, Op>,
    H: Hmac,
{
    fn read_modulus(&self, modulus: &mut [u8]) -> Result<(), ErrorCode> {
        let index = self.key_counter.get();
        let end_index = (index + modulus.len()).min(P_LEN);
        modulus.copy_from_slice(&NistP256Constants::N[index..end_index]);
        self.key_counter.set(end_index);
        Ok(())
    }

    fn read_number(&self, num: &mut [u8]) {
        let index = self.input_counter.get();
        match self.state.get() {
            State::ModHash => {
                let counter = self.hash_storage.map_or(0, |hash| {
                    let mut counter = 0;
                    num.iter_mut().zip(hash.iter().skip(index)).for_each(
                        |(driver_byte, hash_byte)| {
                            *driver_byte = *hash_byte;
                            counter += 1;
                        },
                    );
                    counter
                });
                if counter + index < P_LEN {
                    self.input_counter.set(counter + index);
                } else {
                    self.input_counter.set(0);
                }
            }
            State::MathRDaMul(Operand::First) => {
                let counter = self.read_var_to_buf(&self.r_val, index, num);
                if counter + index < 32 {
                    self.input_counter.set(counter + index);
                } else {
                    self.state.set(State::MathRDaMul(Operand::Second));
                    self.input_counter.set(0);
                }
            }
            State::MathRDaMul(Operand::Second) => {
                self.signing_key.map(|key| {
                    let mut counter = 0;
                    key.iter().skip(index).zip(num.iter_mut()).for_each(
                        |(key_byte, driver_byte)| {
                            *driver_byte = *key_byte;
                            counter += 1;
                        },
                    );
                    if counter + index < 32 {
                        self.input_counter.set(counter + index);
                    } else {
                        self.state.set(State::MathResHAdd(Operand::First));
                        self.input_counter.set(0);
                    }
                });
            }
            State::MathResHAdd(Operand::First) | State::MathResKDiv(Operand::First) => {
                let counter = self.read_var_to_buf(&self.s_val, index, num);
                if counter + index < 32 {
                    self.input_counter.set(counter + index);
                } else {
                    if matches!(self.state.get(), State::MathResHAdd(_)) {
                        self.state.set(State::MathResHAdd(Operand::Second));
                    } else {
                        self.state.set(State::MathResKDiv(Operand::Second));
                    }
                    self.input_counter.set(0);
                }
            }
            State::MathResHAdd(Operand::Second) => {
                self.hash_storage.map(|hash| {
                    let mut counter = 0;
                    hash.iter().skip(index).zip(num.iter_mut()).for_each(
                        |(hash_byte, driver_byte)| {
                            *driver_byte = *hash_byte;
                            counter += 1;
                        },
                    );
                    if counter + index < 32 {
                        self.input_counter.set(counter + index);
                    } else {
                        self.state.set(State::MathResKDiv(Operand::First));
                        self.input_counter.set(0);
                    }
                });
            }
            State::MathResKDiv(Operand::Second) => {
                let counter = self.read_var_to_buf(&self.k_val, index, num);
                self.input_counter.set(counter + index);
            }
            _ => {}
        }
    }

    fn write_number(&self, num: &[u8]) -> Result<(), ErrorCode> {
        match self.state.get() {
            State::ModHash => {
                let index = self.output_counter.get();
                let end_index = (index + num.len()).min(P_LEN);
                self.hash_storage.map(|hash| {
                    hash[index..end_index].copy_from_slice(num);
                });
                self.output_counter.set(end_index);
            }
            _ => {
                let index = self.output_counter.get();
                let counter = self.update_var_from_buf(&self.s_val, index, num);
                self.output_counter.set(index + counter);
            }
        }
        Ok(())
    }

    fn computation_completed(&self, result: Result<(), ErrorCode>) {
        match self.state.get() {
            State::ModHash => {
                self.math.take();
                self.state.set(State::HmacDerivingK1);
                self.input_counter.set(0);
                self.output_counter.set(0);
                self.key_counter.set(0);
                self.hmac_handle
                    .map(|handle| self.hmac_mutex.request(handle));
            }
            State::MathRDaMul(_) => {
                self.math
                    .map(|math| math.start_computation(P_LEN, OpAddition::addition()));
            }
            State::MathResHAdd(_) => {
                self.math
                    .map(|math| math.start_computation(P_LEN, OpDivision::division()));
            }
            _ => {
                self.math.take();
                self.complete_signature(result);
            }
        }
    }
}

impl<'a, E, Op, M, H> hil::public_key_crypto::keys::SetKeyBySlice<'a, 32>
    for EcdsaP256SignatureSigner<'a, E, Op, M, H>
where
    E: EccCrypto<'a, 32, NistP256Constants>,
    Op: OpAddition + OpMultiplication + OpDivision + OpModulo,
    M: MathCryptoBase<'a, Op>,
    H: Hmac,
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

impl<'a, E, Op, M, H> kernel::deferred_call::DeferredCallClient
    for EcdsaP256SignatureSigner<'a, E, Op, M, H>
where
    E: EccCrypto<'a, 32, NistP256Constants>,
    Op: OpAddition + OpMultiplication + OpDivision + OpModulo,
    M: MathCryptoBase<'a, Op>,
    H: Hmac,
{
    fn handle_deferred_call(&self) {
        match self.state.get() {
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
