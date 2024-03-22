//! # alphanet-instructions
//!
//! Custom instructions for Alphanet.

use revm_interpreter::Instruction;

/// EIP-3074 custom instructions.
pub mod eip3074;

/// Association of OpCode and correspondent instruction.
#[derive(Clone, Debug)]
pub struct InstructionWithOpCode<H> {
    /// Opcode.
    pub opcode: u8,
    /// Instruction.
    pub instruction: Instruction<H>,
}
