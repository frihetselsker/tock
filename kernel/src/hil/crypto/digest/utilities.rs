use crate::ErrorCode;

pub trait ModeToken {}

pub enum DigestMode {
    Md5(Option<Md5Token>),
    Sha1(Option<Sha1Token>),
    Sha224(Option<Sha224Token>),
    Sha256(Option<Sha256Token>),
    Sha384(Option<Sha384Token>),
    Sha512_224(Option<Sha512_224Token>),
    Sha512_256(Option<Sha512_256Token>),
    Sha512(Option<Sha512Token>),
}

impl DigestMode {
    fn is_empty(&self) -> bool {
        match self {
            DigestMode::Md5(Some(_))
            | DigestMode::Sha1(Some(_))
            | DigestMode::Sha224(Some(_))
            | DigestMode::Sha256(Some(_))
            | DigestMode::Sha384(Some(_))
            | DigestMode::Sha512_224(Some(_))
            | DigestMode::Sha512_256(Some(_))
            | DigestMode::Sha512(Some(_)) => true,
            _ => false,
        }
    }
}

impl Default for DigestMode {
    fn default() -> Self {
        Self::Sha256(None)
    }
}

pub struct Sha512Token;
pub struct Sha512_224Token;
pub struct Sha512_256Token;
pub struct Sha256Token;
pub struct Sha224Token;
pub struct Sha1Token;
pub struct Sha384Token;
pub struct Md5Token;

impl ModeToken for Sha512Token {}
impl ModeToken for Sha512_224Token {}
impl ModeToken for Sha512_256Token {}
impl ModeToken for Sha256Token {}
impl ModeToken for Sha224Token {}
impl ModeToken for Sha1Token {}
impl ModeToken for Sha384Token {}
impl ModeToken for Md5Token {}

pub trait Algotithm {
    const DIGEST_LEN: usize;
    const BLOCK_SIZE: usize;

    type Slice: AsMut<[u8]>;
    type Token: ModeToken;
}

struct Sha512;

impl Algotithm for Sha512 {
    const BLOCK_SIZE: usize = 1024 >> 3;
    const DIGEST_LEN: usize = 64;

    type Slice = [u8; Self::DIGEST_LEN];
    type Token = Sha512Token;
}

struct Sha512_256;

impl Algotithm for Sha512_256 {
    const BLOCK_SIZE: usize = 1024 >> 3;
    const DIGEST_LEN: usize = 32;

    type Slice = [u8; Self::DIGEST_LEN];
    type Token = Sha512_256Token;
}

struct Sha512_224;

impl Algotithm for Sha512_224 {
    const BLOCK_SIZE: usize = 1024 >> 3;
    const DIGEST_LEN: usize = 28;

    type Slice = [u8; Self::DIGEST_LEN];
    type Token = Sha512_224Token;
}

struct Sha384;

impl Algotithm for Sha384 {
    const BLOCK_SIZE: usize = 1024 >> 3;
    const DIGEST_LEN: usize = 48;

    type Slice = [u8; Self::DIGEST_LEN];
    type Token = Sha384Token;
}

struct Sha256;

impl Algotithm for Sha256 {
    const BLOCK_SIZE: usize = 512 >> 3;
    const DIGEST_LEN: usize = 32;

    type Slice = [u8; Self::DIGEST_LEN];
    type Token = Sha256Token;
}

struct Sha224;

impl Algotithm for Sha224 {
    const BLOCK_SIZE: usize = 512 >> 3;
    const DIGEST_LEN: usize = 28;

    type Slice = [u8; Self::DIGEST_LEN];
    type Token = Sha224Token;
}

struct Sha1;

impl Algotithm for Sha1 {
    const BLOCK_SIZE: usize = 512 >> 3;
    const DIGEST_LEN: usize = 20;

    type Slice = [u8; Self::DIGEST_LEN];
    type Token = Sha1Token;
}

struct Md5;

impl Algotithm for Md5 {
    const BLOCK_SIZE: usize = 512 >> 3;
    const DIGEST_LEN: usize = 16;

    type Slice = [u8; Self::DIGEST_LEN];
    type Token = Md5Token;
}

pub enum DigestSlice<'a> {
    Slice16(&'a [u8; 16]),
    Slice20(&'a [u8; 20]),
    Slice28(&'a [u8; 28]),
    Slice32(&'a [u8; 32]),
    Slice48(&'a [u8; 48]),
    Slice64(&'a [u8; 64]),
}

impl<'a> DigestSlice<'a> {
    pub fn new(digest: &'a [u8]) -> Result<Self, (ErrorCode, &'a [u8])> {
        match digest.len() {
            16 => match TryInto::<&'a [u8; 16]>::try_into(digest) {
                Ok(buf) => Ok(DigestSlice::Slice16(buf)),
                Err(_) => Err((ErrorCode::INVAL, digest)),
            },
            20 => match TryInto::<&'a [u8; 20]>::try_into(digest) {
                Ok(buf) => Ok(DigestSlice::Slice20(buf)),
                Err(_) => Err((ErrorCode::INVAL, digest)),
            },
            28 => match TryInto::<&'a [u8; 28]>::try_into(digest) {
                Ok(buf) => Ok(DigestSlice::Slice28(buf)),
                Err(_) => Err((ErrorCode::INVAL, digest)),
            },
            32 => match TryInto::<&'a [u8; 32]>::try_into(digest) {
                Ok(buf) => Ok(DigestSlice::Slice32(buf)),
                Err(_) => Err((ErrorCode::INVAL, digest)),
            },
            48 => match TryInto::<&'a [u8; 48]>::try_into(digest) {
                Ok(buf) => Ok(DigestSlice::Slice48(buf)),
                Err(_) => Err((ErrorCode::INVAL, digest)),
            },
            64 => match TryInto::<&'a [u8; 64]>::try_into(digest) {
                Ok(buf) => Ok(DigestSlice::Slice64(buf)),
                Err(_) => Err((ErrorCode::INVAL, digest)),
            },
            _ => Err((ErrorCode::INVAL, digest)),
        }
    }
}
