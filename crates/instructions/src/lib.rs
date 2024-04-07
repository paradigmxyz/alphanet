//! # AlphaNet instructions
//!
//! Collection of custom OP codes for AlphaNet and related functionality.

#![warn(unused_crate_dependencies)]

use revm_interpreter::opcode::BoxedInstruction;

pub mod context;
pub mod eip3074;

/// Association of OP codes and correspondent boxed instruction.
pub struct BoxedInstructionWithOpCode<'a, H> {
    /// Opcode.
    pub opcode: u8,
    /// Boxed instruction.
    pub boxed_instruction: BoxedInstruction<'a, H>,
}
