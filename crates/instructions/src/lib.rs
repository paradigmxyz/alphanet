//! # alphanet-instructions
//!
//! Custom instructions for Alphanet.

use revm_interpreter::opcode::BoxedInstruction;
use std::{borrow::BorrowMut, cell::RefCell, collections::HashMap, rc::Rc};

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
    /// Sets a value for the given key. Thanks to interior mutability, no need
    /// to define on &mut self.
    pub fn set(&self, key: Vec<u8>, value: Vec<u8>) {
        let mut at = &self.inner;
        let inner_map = at.borrow_mut();
        let new_map: HashMap<Vec<u8>, Vec<u8>> = vec![(key, value)].into_iter().collect();
        let _ = inner_map.replace(new_map);
    }

    /// Gets the value for the given key, if any.
    pub fn get(&self, key: Vec<u8>) -> Option<Vec<u8>> {
        let inner_map = self.inner.borrow();
        inner_map.get(&key).cloned()
    }

    /// Empties inner state.
    pub fn reset(&mut self) {
        self.inner = Rc::new(RefCell::new(HashMap::default()));
    }
}
