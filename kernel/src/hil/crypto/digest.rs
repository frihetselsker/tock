use crate::ErrorCode;
use crate::utilities::leasable_buffer::SubSliceMutImmut;

#[derive(Clone, Copy, Default)]
pub enum TransferMode {
    #[default]
    DirectStream,
    DMA,
}

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
    pub const fn get_digest_len(&self) -> usize {
        match self {
            Mode::Md5 => 16,
            Mode::Sha1 => 20,
            Mode::Sha224 | Mode::Sha512_224 => 28,
            Mode::Sha256 | Mode::Sha512_256 => 32,
            Mode::Sha384 => 48,
            Mode::Sha512 => 64,
        }
    }
    pub const fn get_block_size(&self) -> usize {
        match self {
            Mode::Md5 | Mode::Sha1 | Mode::Sha224 | Mode::Sha256 => 512 >> 3,
            Mode::Sha384 | Mode::Sha512_224 | Mode::Sha512_256 | Mode::Sha512 => 1024 >> 3,
        }
    }
}

pub trait Digest {
    fn hash(&self, mode: Mode, len: usize) -> Result<TransferMode, ErrorCode>;
    fn feed_dma_buffer(
        &self,
        dma_buffer: SubSliceMutImmut<'static, u8>,
    ) -> Result<(), (ErrorCode, SubSliceMutImmut<'static, u8>)>;
    fn clear_data(&self);
    fn set_client(&self, client: &'static dyn Client);
}

pub trait Client {
    fn read_input(&self, input: &mut [u8]) -> Result<usize, ErrorCode>;
    fn write_output(&self, output: &[u8]) -> Result<(), ErrorCode>;
    fn dma_buffer_done(
        &self,
        result: Result<(), ErrorCode>,
        dma_buffer: SubSliceMutImmut<'static, u8>,
    );
    fn hash_done(&self, result: Result<(), ErrorCode>);
}

pub trait Hmac: Digest {
    fn authenticate(
        &self,
        mode: Mode,
        input_len: usize,
        key_len: usize,
    ) -> Result<TransferMode, ErrorCode>;

    fn set_hmac_client(&self, client: &'static dyn HmacClient);
}

pub trait HmacClient: Client {
    fn read_key(&self, key: &mut [u8]) -> Result<usize, ErrorCode>;
}
