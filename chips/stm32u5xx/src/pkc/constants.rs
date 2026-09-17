use kernel::utilities::{
    StaticRef,
    registers::{ReadOnly, ReadWrite, WriteOnly, register_bitfields, register_structs},
};

register_structs! {
    pub(crate) PkaRegisters {
        /// PKA control register
        (0x00 => pub(crate) cr: ReadWrite<u32, CR::Register>),

        /// PKA status register
        (0x04 => pub(crate) sr: ReadOnly<u32, SR::Register>),

        /// PKA clear flag register
        (0x08 => pub(crate) clrfr: WriteOnly<u32, CLRFR::Register>),

        (0x0C => _reserved0),

        /// PKA RAM
        /// 0x14D8-0x400 is 0x10D8 bytes, which is 4312 bytes in decimal. We divide by the size of u32 (4 bytes)
        /// Two 32-bit slices would correspond to one 64-bit "word" as defined in datasheet
        (0x400 => pub(crate) ram: [ReadWrite<u32>; (0x14D8 - 0x400) / size_of::<u32>()]),

        (0x14D8 => @END),
    }
}

register_bitfields! [u32,
    pub(crate) CR [
        /// Operation error interrupt enable
        OPERRIE OFFSET(21) NUMBITS(1) [],

        /// Address error interrupt enable
        ADDERRIE OFFSET(20) NUMBITS(1) [],

        /// RAM error interrupt enable
        RAMERRIE OFFSET(19) NUMBITS(1) [],

        /// End of operation interrupt enable
        PROCENDIE OFFSET(17) NUMBITS(1) [],

        /// PKA operation code
        MODE OFFSET(8) NUMBITS(6) [
            /// Montogomery parameter computation then modular exponentioantion
            MontgomeryModularExp = 0b000000,

            /// Montgomery parameter computation only
            MontgomeryOnly = 0b000001,

            /// Modular exponentiation only (Montgomery parameter must be loaded first)
            ModularExpOnly = 0b000010,

            /// Modular exponentiation (protected, used when manipulating secrets)
            ModularExp = 0b000011,

            /// Montgomery parameter computation then ECC scalar multiplication (protected)
            MontgomeryECC = 0b100000,

            /// ECDSA sign (protected)
            ECDSASign = 0b100100,

            /// ECDSA verification
            ECDSAVerfication = 0b100110,

            /// Point on elliptic curve Fp check
            FpCheck = 0b101000,

            /// RSA CRT exponentiation
            RSACRTExp = 0b000111,

            /// Modular inversion
            ModularInversion = 0b001000,

            /// Arithmetic addition
            ArithmeticAddition = 0b001001,

            /// Arithmetic substraction
            ArithmeticSubstraction = 0b001010,

            /// Arithmetic multiplication
            ArithmeticMultiplication = 0b001011,

            /// Arithmetic comparison
            ArithmeticComparison = 0b001100,

            /// Modular reduction
            ModularReduction = 0b001101,

            /// Modular addition
            ModularAddition = 0b001110,

            /// Modular substraction
            ModularSubstraction = 0b001111,

            /// Montgomery multiplication
            MontgomeryMultiplication = 0b010000,

            /// ECC complete addition
            ECCCompleteAddition = 0b100011,

            /// ECC double base ladder
            ECCDoubleBaseLadder = 0b100111,

            /// ECC projective to affine
            ECCProjectiveToAffine = 0b101111,
        ],

        /// Start the operation
        START OFFSET(1) NUMBITS(1) [],

        /// PKA enable
        EN OFFSET(0) NUMBITS(1) [],
    ],

    pub(crate) SR [
        /// Operation error flag
        OPERRF OFFSET(21) NUMBITS(1) [],

        /// Address error flag
        ADDRERRF OFFSET(20) NUMBITS(1) [],

        /// PKA RAM Error flag
        RAMERRF OFFSET(19) NUMBITS(1) [],

        /// PKA end of operation flag
        PROCENDF OFFSET(17) NUMBITS(1) [],

        /// Busy flag
        BUSY OFFSET(16) NUMBITS(1) [],

        /// PKA initialization OK
        INITOK OFFSET(0) NUMBITS(1) [],
    ],

    pub(crate) CLRFR [
        /// Clear oferation error flag
        OPERRFC OFFSET(21) NUMBITS(1) [],

        /// Clear address error flag
        ADDERRFC OFFSET(20) NUMBITS(1) [],

        /// Clear PKA RAM error flag
        RAMERRFC OFFSET(19) NUMBITS(1) [],

        /// Clear PKA end of op flag
        PROCENDFC OFFSET(17) NUMBITS(1) [],
    ]
];

/// Base address for PKA registers
pub(crate) const PKA_BASE: StaticRef<PkaRegisters> =
    unsafe { StaticRef::new(0x520C2000 as *const PkaRegisters) };

/// Start of the RAM region
const RAM_START: usize = 0x400;

/// Addresses for montgomery modular exponentiation mode
/// Exponent length address
const EXP_LEN_ADDR: usize = 0x400;
/// Operand length address
const OP_LEN_ADDR: usize = 0x408;
/// Operand A (base of exponentiation) address
const OP_A_ADDR: usize = 0xC68;
/// Exponent address
const EXP_ADDR: usize = 0xE78;
/// Modulus value address
const MOD_VALUE_ADDR: usize = 0x1088;
/// Result address
const RESULT_ADDR: usize = 0x838;

/// Addresses for ECC Fp scalar multiplication mode
/// Curve prime order length
const PRIME_ORDER_LEN_ADDR: usize = 0x400;
/// Curve modulus length address
const CURVE_MODULUS_LEN_ADDR: usize = 0x408;
/// Curve coefficient a sign address
const CURVE_A_SIGN_LEN_ADDR: usize = 0x410;
/// Curve coefficient a absolute value address
const CURVE_A_ADDR: usize = 0x418;
/// Curve coefficient b address
const CURVE_B_ADDR: usize = 0x520;
/// Curve modulus value address
const CURVE_MODULUS_ADDR: usize = 0x1088;
/// Scalar multiplier address
const K_ADDR: usize = 0x12A0;
/// Point X coordinate address
const X_ADDR: usize = 0x578;
/// Point Y coordinate address
const Y_ADDR: usize = 0x470;
/// Curve prime order address
const PRIME_ORDER_ADDR: usize = 0xF88;
/// Result X coordinate address
const RESULT_X_ADDR: usize = 0x578;
/// Result Y coordinate address
const RESULT_Y_ADDR: usize = 0x5D0;
/// Error check address
const ERR_CHECK_ADDR: usize = 0x5D0;
/// Errors occured
const ERRORS_OCCURED: usize = 0xCBC9;
/// No Errors occured
const NO_ERRORS_OCCURED: usize = 0xD60D;

/// RAM array mapping
/// We need to compute the offset from the RAM start, and divide by the size of u32 to obtain its index in the RAM array
const fn calc_idx(addr: usize) -> usize {
    (addr - RAM_START) / size_of::<u32>()
}

pub(crate) const EXP_LEN_IDX: usize = calc_idx(EXP_LEN_ADDR);
pub(crate) const OP_LEN_IDX: usize = calc_idx(OP_LEN_ADDR);
pub(crate) const OP_A_IDX: usize = calc_idx(OP_A_ADDR);
pub(crate) const EXP_IDX: usize = calc_idx(EXP_ADDR);
pub(crate) const MOD_VALUE_IDX: usize = calc_idx(MOD_VALUE_ADDR);
pub(crate) const RESULT_IDX: usize = calc_idx(RESULT_ADDR);
pub(crate) const PRIME_ORDER_LEN_IDX: usize = calc_idx(PRIME_ORDER_LEN_ADDR);
pub(crate) const CURVE_MODULUS_LEN_IDX: usize = calc_idx(CURVE_MODULUS_LEN_ADDR);
pub(crate) const CURVE_A_SIGN_LEN_IDX: usize = calc_idx(CURVE_A_SIGN_LEN_ADDR);
pub(crate) const CURVE_A_IDX: usize = calc_idx(CURVE_A_ADDR);
pub(crate) const CURVE_B_IDX: usize = calc_idx(CURVE_B_ADDR);
pub(crate) const CURVE_MODULUS_IDX: usize = calc_idx(CURVE_MODULUS_ADDR);
pub(crate) const K_IDX: usize = calc_idx(K_ADDR);
pub(crate) const X_IDX: usize = calc_idx(X_ADDR);
pub(crate) const Y_IDX: usize = calc_idx(Y_ADDR);
pub(crate) const PRIME_ORDER_IDX: usize = calc_idx(PRIME_ORDER_ADDR);
pub(crate) const RESULT_X_IDX: usize = calc_idx(RESULT_X_ADDR);
pub(crate) const RESULT_Y_IDX: usize = calc_idx(RESULT_Y_ADDR);
pub(crate) const ERR_CHECK_IDX: usize = calc_idx(ERR_CHECK_ADDR);
