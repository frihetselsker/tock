// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! nRF52840 CCM register and DMA management.

use kernel::utilities::StaticRef;
use kernel::utilities::cells::MapCell;
use kernel::utilities::dma_slice::DmaSliceMut;
use kernel::utilities::registers::interfaces::{Readable, Writeable};
use kernel::utilities::registers::{ReadOnly, ReadWrite, WriteOnly, register_bitfields};

pub const CCM_CONFIG_START: usize = 0;
pub const CCM_CONFIG_SIZE: usize = 33;
pub const CCM_INPUT_START: usize = 36;
pub const CCM_MAX_PAYLOAD_SIZE: usize = 251;
pub const CCM_TAG_SIZE: usize = 4;
pub const CCM_PACKET_HEADER_SIZE: usize = 3;
pub const CCM_PACKET_BUFFER_SIZE: usize =
    CCM_PACKET_HEADER_SIZE + CCM_MAX_PAYLOAD_SIZE + CCM_TAG_SIZE;
pub const CCM_OUTPUT_START: usize = CCM_INPUT_START + CCM_PACKET_BUFFER_SIZE.div_ceil(4) * 4;
pub const CCM_SCRATCH_START: usize = CCM_OUTPUT_START + CCM_PACKET_BUFFER_SIZE.div_ceil(4) * 4;
pub const CCM_SCRATCH_SIZE: usize = (16 + CCM_MAX_PAYLOAD_SIZE).div_ceil(4) * 4;
pub const CCM_DATA_SIZE: usize = CCM_SCRATCH_START + CCM_SCRATCH_SIZE;

#[repr(C, align(4))]
pub struct CcmData([u8; CCM_DATA_SIZE]);

impl CcmData {
    pub const fn new() -> Self {
        Self([0; CCM_DATA_SIZE])
    }

    pub fn as_mut_slice(&'static mut self) -> &'static mut [u8] {
        &mut self.0
    }
}

#[repr(C)]
pub struct CcmRegisters {
    task_ksgen: WriteOnly<u32, Task::Register>,
    _task_crypt: WriteOnly<u32, Task::Register>,
    task_stop: WriteOnly<u32, Task::Register>,
    _task_rateoverride: WriteOnly<u32, Task::Register>,
    _reserved1: [u32; 60],
    event_endksgen: ReadWrite<u32, Event::Register>,
    event_endcrypt: ReadWrite<u32, Event::Register>,
    event_error: ReadWrite<u32, Event::Register>,
    _reserved2: [u32; 61],
    shorts: ReadWrite<u32, Short::Register>,
    _reserved3: [u32; 64],
    intenset: ReadWrite<u32, Interrupt::Register>,
    intenclr: ReadWrite<u32, Interrupt::Register>,
    _reserved4: [u32; 61],
    micstatus: ReadOnly<u32, MicStatus::Register>,
    _reserved5: [u32; 63],
    enable: ReadWrite<u32, Enable::Register>,
    mode: ReadWrite<u32, Mode::Register>,
    cnfptr: ReadWrite<u32, Pointer::Register>,
    inptr: ReadWrite<u32, Pointer::Register>,
    outptr: ReadWrite<u32, Pointer::Register>,
    scratchptr: ReadWrite<u32, Pointer::Register>,
    maxpacketsize: ReadWrite<u32, MaxPacketSize::Register>,
    _rateoverride: ReadWrite<u32>,
}

register_bitfields! [u32,
    Task [
        TRIGGER OFFSET(0) NUMBITS(1)
    ],

    Event [
        READY OFFSET(0) NUMBITS(1)
    ],

    Short [
        ENDKSGEN_CRYPT OFFSET(0) NUMBITS(1)
    ],

    Interrupt [
        ENDKSGEN OFFSET(0) NUMBITS(1),
        ENDCRYPT OFFSET(1) NUMBITS(1),
        ERROR OFFSET(2) NUMBITS(1)
    ],

    MicStatus [
        STATUS OFFSET(0) NUMBITS(1) [
            CheckFailed = 0,
            CheckPassed = 1
        ]
    ],

    Enable [
        ENABLE OFFSET(0) NUMBITS(2) [
            Disabled = 0,
            Enabled = 2
        ]
    ],

    Mode [
        MODE OFFSET(0) NUMBITS(1) [
            Encryption = 0,
            Decryption = 1
        ],
        DATARATE OFFSET(16) NUMBITS(2) [
            M1 = 0
        ],
        LENGTH OFFSET(24) NUMBITS(1) [
            Extended = 1
        ]
    ],

    Pointer [
        POINTER OFFSET(0) NUMBITS(32)
    ],

    MaxPacketSize [
        SIZE OFFSET(0) NUMBITS(8)
    ]
];

pub enum CcmDmaResult {
    Complete {
        buffer: &'static mut [u8],
        mic_valid: bool,
    },
    Error(&'static mut [u8]),
}

pub struct CcmRegistersManager {
    registers: StaticRef<CcmRegisters>,
    dma_buf: MapCell<DmaSliceMut<'static, u8>>,
}

impl CcmRegistersManager {
    /// Create a new CCM registers manager.
    ///
    /// # Safety
    ///
    /// `registers` must point to the CCM peripheral on an nRF52840. This must
    /// only be called once, and the returned manager must be the only code that
    /// controls the CCM DMA registers.
    pub unsafe fn new(registers: StaticRef<CcmRegisters>) -> Self {
        Self {
            registers,
            dma_buf: MapCell::empty(),
        }
    }

    pub fn start_ccm_dma(
        &self,
        buffer: &'static mut [u8],
        decrypt: bool,
    ) -> Result<(), &'static mut [u8]> {
        if self.dma_buf.is_some()
            || buffer.len() != CCM_DATA_SIZE
            || !buffer.as_ptr().addr().is_multiple_of(4)
        {
            return Err(buffer);
        }

        // To create a DmaFence we must trust the architecture implementation.
        //
        // ### Safety
        //
        // The architecture-provided version is correct for the nRF52840.
        let fence = unsafe { cortexm4f::dma_fence::CortexMDmaFence::new() };
        let dma_slice = DmaSliceMut::new_static(buffer, fence);
        let base = dma_slice.ptr_addr();

        self.registers.event_endksgen.write(Event::READY::CLEAR);
        self.registers.event_endcrypt.write(Event::READY::CLEAR);
        self.registers.event_error.write(Event::READY::CLEAR);
        self.registers.shorts.write(Short::ENDKSGEN_CRYPT::SET);
        self.registers
            .cnfptr
            .write(Pointer::POINTER.val((base + CCM_CONFIG_START) as u32));
        self.registers
            .inptr
            .write(Pointer::POINTER.val((base + CCM_INPUT_START) as u32));
        self.registers
            .outptr
            .write(Pointer::POINTER.val((base + CCM_OUTPUT_START) as u32));
        self.registers
            .scratchptr
            .write(Pointer::POINTER.val((base + CCM_SCRATCH_START) as u32));
        self.registers
            .maxpacketsize
            .write(MaxPacketSize::SIZE.val(CCM_MAX_PAYLOAD_SIZE as u32));
        self.registers.enable.write(Enable::ENABLE::Enabled);

        let operation = if decrypt {
            Mode::MODE::Decryption
        } else {
            Mode::MODE::Encryption
        };
        self.registers
            .mode
            .write(operation + Mode::DATARATE::M1 + Mode::LENGTH::Extended);
        self.registers
            .intenset
            .write(Interrupt::ENDCRYPT::SET + Interrupt::ERROR::SET);

        self.dma_buf.replace(dma_slice);
        self.registers.task_ksgen.write(Task::TRIGGER::SET);
        Ok(())
    }

    pub fn handle_interrupt(&self) -> Option<CcmDmaResult> {
        let error = self.registers.event_error.is_set(Event::READY);
        let complete = self.registers.event_endcrypt.is_set(Event::READY);
        if !error && !complete {
            return None;
        }

        self.registers
            .intenclr
            .write(Interrupt::ENDKSGEN::SET + Interrupt::ENDCRYPT::SET + Interrupt::ERROR::SET);
        if error {
            self.registers.task_stop.write(Task::TRIGGER::SET);
        }
        let mic_valid = self
            .registers
            .micstatus
            .matches_all(MicStatus::STATUS::CheckPassed);
        self.registers.event_endksgen.write(Event::READY::CLEAR);
        self.registers.event_endcrypt.write(Event::READY::CLEAR);
        self.registers.event_error.write(Event::READY::CLEAR);
        self.registers.shorts.set(0);
        self.registers.enable.write(Enable::ENABLE::Disabled);

        self.dma_buf.take().map(|dma_slice| {
            // To create a DmaFence we must trust the architecture implementation.
            //
            // ### Safety
            //
            // The architecture-provided version is correct for the nRF52840.
            let fence = unsafe { cortexm4f::dma_fence::CortexMDmaFence::new() };

            // ### Safety
            //
            // ENDCRYPT or ERROR was observed above and the peripheral is now
            // disabled, so the CCM hardware can no longer access the buffer.
            let buffer = unsafe { dma_slice.take(fence) };
            if error {
                CcmDmaResult::Error(buffer)
            } else {
                CcmDmaResult::Complete { buffer, mic_valid }
            }
        })
    }
}
