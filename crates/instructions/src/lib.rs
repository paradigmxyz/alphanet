//! # alphanet-instructions
//!
//! Custom instructions for Alphanet.

#![warn(unused_crate_dependencies)]

use revm_interpreter::opcode::BoxedInstruction;

/// EIP-3074 custom instructions.
pub mod eip3074;

/// Instructions context.
pub mod context;

/// Association of OpCode and correspondent boxed instruction.
pub struct BoxedInstructionWithOpCode<'a, H> {
    /// Opcode.
    pub opcode: u8,
    /// Boxed instruction.
    pub boxed_instruction: BoxedInstruction<'a, H>,
}
