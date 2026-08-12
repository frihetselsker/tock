use crate::ErrorCode;

#[derive(Clone, Copy)]
pub enum Mode {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512_224,
    Sha512_256,
    Sha512,
}

impl Mode {
    fn get_digest_len(&self) -> usize {
        match self {
            Mode::Md5 => 16,
            Mode::Sha1 => 20,
            Mode::Sha224 | Mode::Sha512_224 => 28,
            Mode::Sha256 | Mode::Sha512_256 => 32,
            Mode::Sha384 => 48,
            Mode::Sha512 => 64,
        }
    }
    fn get_block_size(&self) -> usize {
        match self {
            Mode::Md5 | Mode::Sha1 | Mode::Sha224 | Mode::Sha256 => 512 >> 3,
            Mode::Sha384 | Mode::Sha512_224 | Mode::Sha512_256 | Mode::Sha512 => 1024 >> 3,
        }
    }
}

pub trait Digest {
    fn hash(&self, mode: Mode, len: usize) -> Result<(), ErrorCode>;
    fn clear_data(&self);
    fn set_client(&self, client: &dyn Client);
}

pub trait Client {
    fn read_input(&self, input: &mut [u8]) -> Result<usize, ErrorCode>;
    fn write_output(&self, output: &[u8]) -> Result<(), ErrorCode>;
    fn hash_done(&self, result: Result<(), ErrorCode>);
}

pub trait Hmac: Digest {}

pub trait HmacClient: Client {
    fn read_key(&self, key: &[u8]) -> Result<(), ErrorCode>;
}
