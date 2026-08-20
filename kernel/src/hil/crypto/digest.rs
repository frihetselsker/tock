use crate::ErrorCode;

#[derive(Clone, Copy)]
pub enum Algorithm {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512_224,
    Sha512_256,
    Sha512,
}

impl Algorithm {
    pub const fn get_digest_len(&self) -> usize {
        match self {
            Algorithm::Md5 => 16,
            Algorithm::Sha1 => 20,
            Algorithm::Sha224 | Algorithm::Sha512_224 => 28,
            Algorithm::Sha256 | Algorithm::Sha512_256 => 32,
            Algorithm::Sha384 => 48,
            Algorithm::Sha512 => 64,
        }
    }
    pub const fn get_block_size(&self) -> usize {
        match self {
            Algorithm::Md5 | Algorithm::Sha1 | Algorithm::Sha224 | Algorithm::Sha256 => 512 >> 3,
            Algorithm::Sha384
            | Algorithm::Sha512_224
            | Algorithm::Sha512_256
            | Algorithm::Sha512 => 1024 >> 3,
        }
    }
}

pub trait Digest {
    fn hash(&self, mode: Algorithm, len: usize) -> Result<(), ErrorCode>;
    fn clear_data(&self);
    fn set_client(&self, client: &'static dyn Client);
}

pub trait Client {
    fn read_input(&self, input: &mut [u8]) -> Result<usize, ErrorCode>;
    fn write_output(&self, output: &[u8]) -> Result<(), ErrorCode>;
    fn hash_done(&self, result: Result<(), ErrorCode>);
}

pub trait Hmac: Digest {
    fn authenticate(
        &self,
        algorithm: Algorithm,
        input_len: usize,
        key_len: usize,
    ) -> Result<(), ErrorCode>;

    fn set_hmac_client(&self, client: &'static dyn HmacClient);
}

pub trait HmacClient: Client {
    fn read_key(&self, key: &mut [u8]) -> Result<usize, ErrorCode>;
}
