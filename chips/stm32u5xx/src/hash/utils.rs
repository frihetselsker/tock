use core::cell::Cell;

use kernel::{
    ErrorCode,
    hil::crypto::digest::{DigestClient, Md5, Sha1, Sha224, Sha256},
};

pub(crate) const FIFO_SIZE: usize = 17 * 4;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum State {
    Idle { is_intermediate: bool },
    Feeding,
    Finishing { is_started: bool },
}

#[derive(Clone, Copy)]
pub(crate) enum Client {
    Md5(&'static dyn DigestClient<Md5>),
    Sha1(&'static dyn DigestClient<Sha1>),
    Sha224(&'static dyn DigestClient<Sha224>),
    Sha256(&'static dyn DigestClient<Sha256>),
}

impl Client {
    pub(crate) fn read_input(self, input: &mut [u8]) -> Result<usize, ErrorCode> {
        let count = match self {
            Self::Md5(client) => client.read_input(input),
            Self::Sha1(client) => client.read_input(input),
            Self::Sha224(client) => client.read_input(input),
            Self::Sha256(client) => client.read_input(input),
        }?;
        if count == 0 || count > input.len() {
            Err(ErrorCode::SIZE)
        } else {
            Ok(count)
        }
    }

    pub(crate) fn update_done(self, result: Result<(), ErrorCode>) {
        match self {
            Self::Md5(client) => client.update_done(result),
            Self::Sha1(client) => client.update_done(result),
            Self::Sha224(client) => client.update_done(result),
            Self::Sha256(client) => client.update_done(result),
        }
    }

    pub(crate) fn digest_done(self, result: Result<(), ErrorCode>) {
        match self {
            Self::Md5(client) => client.digest_done(result),
            Self::Sha1(client) => client.digest_done(result),
            Self::Sha224(client) => client.digest_done(result),
            Self::Sha256(client) => client.digest_done(result),
        }
    }
}

pub(crate) enum ClientCallback {
    UpdateDone,
    OpDone,
}

pub(crate) struct Leftover {
    partial: Cell<[u8; 4]>,
    partial_len: Cell<usize>,
}

impl Leftover {
    pub(crate) fn new() -> Self {
        Self {
            partial: Cell::new([0u8; 4]),
            partial_len: Cell::new(0),
        }
    }

    pub(crate) fn add(&self, byte: u8) -> Result<(), ErrorCode> {
        if !self.is_full() {
            self.partial.update(|mut slice| {
                slice[self.partial_len.get()] = byte;
                self.partial_len.update(|idx| idx + 1);
                slice
            });
            Ok(())
        } else {
            Err(ErrorCode::SIZE)
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.partial_len.get()
    }

    pub(crate) fn to_le(&self) -> u32 {
        self.partial_len.take();
        let mut value = self.partial.take();
        value.reverse();
        u32::from_le_bytes(value).to_be()
    }

    pub(crate) fn is_full(&self) -> bool {
        self.partial_len.get() == 4
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.partial_len.get() == 0
    }

    pub(crate) fn reset(&self) {
        self.partial.take();
        self.partial_len.take();
    }
}
