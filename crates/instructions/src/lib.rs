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
    /// Sets a value for the given key.
    pub fn set(&self, key: Vec<u8>, value: Vec<u8>) {
        let cell = &self.inner;
        let mut map = cell.borrow_mut();
        map.insert(key, value);
    }

    /// Gets the value for the given key, if any.
    pub fn get(&self, key: Vec<u8>) -> Option<Vec<u8>> {
        let map = self.inner.borrow();
        map.get(&key).cloned()
    }

    /// Sets a value for the given &str as key.
    pub fn set_named_variable(&self, key: &str, value: Vec<u8>) {
        self.set(Vec::from(key.as_bytes()), value);
    }

    /// Gets the value for the given &str key, if any.
    pub fn get_named_variable(&self, key: &str) -> Option<Vec<u8>> {
        self.get(Vec::from(key.as_bytes()))
    }

    /// Empties inner state
    pub fn reset(&self) {
        let cell = &self.inner;
        let mut map = cell.borrow_mut();
        map.clear();
    }
}
