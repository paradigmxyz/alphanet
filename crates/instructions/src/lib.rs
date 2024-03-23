//! # alphanet-instructions
//!
//! Custom instructions for Alphanet.

use revm_interpreter::opcode::BoxedInstruction;
use std::{cell::RefCell, collections::HashMap, rc::Rc};

/// EIP-3074 custom instructions.
pub mod eip3074;

/// Association of OpCode and correspondent boxed instruction.
pub struct BoxedInstructionWithOpCode<'a, H> {
    /// Opcode.
    pub opcode: u8,
    /// Boxed instruction.
    pub boxed_instruction: BoxedInstruction<'a, H>,
}

#[derive(Clone, Default)]
/// Context variables to be used in instructions. The data set here is expected
/// to live for the duration of a single transaction.
pub struct InstructionsContext {
    /// Contains the actual variables. Is meant to be accessed both for reads
    /// and writes using interior mutability, so that the Instruction and
    /// BoxedInstruction signatures are observed.
    pub inner: Rc<RefCell<HashMap<Vec<u8>, Vec<u8>>>>,
}

impl InstructionsContext {
    /// Empties inner state.
    pub fn reset(&mut self) {
        self.inner = Rc::new(RefCell::new(HashMap::default()));
    }
}
