use revm::{Database, Inspector};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

#[derive(Clone, Default)]
/// Context variables to be used in instructions. The data set here is expected
/// to live for the duration of a single transaction.
pub struct InstructionsContext {
    /// Contains the actual variables. Is meant to be accessed both for reads
    /// and writes using interior mutability, so that the Instruction and
    /// BoxedInstruction signatures are observed.
    inner: Rc<RefCell<HashMap<Vec<u8>, Vec<u8>>>>,
}

impl InstructionsContext {
    /// Sets a value for the given key.
    fn set(&self, key: Vec<u8>, value: Vec<u8>) {
        let cell = &self.inner;
        let mut map = cell.borrow_mut();
        map.insert(key, value);
    }

    /// Gets the value for the given key, if any.
    fn get(&self, key: Vec<u8>) -> Option<Vec<u8>> {
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

    /// Empties inner state.
    pub fn clear(&self) {
        let cell = &self.inner;
        let mut map = cell.borrow_mut();
        map.clear();
    }
}

/// Inspector to manage instructions context.
pub struct InstructionsContextInspector {
    instructions_context: InstructionsContext,
}

impl InstructionsContextInspector {
    /// Constructor, sets instructions context.
    pub fn new(instructions_context: InstructionsContext) -> Self {
        Self { instructions_context }
    }
}

impl<DB: Database> Inspector<DB> for InstructionsContextInspector {
    fn call_end(
        &mut self,
        _context: &mut revm::EvmContext<DB>,
        _inputs: &revm_interpreter::CallInputs,
        outcome: revm_interpreter::CallOutcome,
    ) -> revm_interpreter::CallOutcome {
        self.instructions_context.clear();
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::{Evm, InMemoryDB};
    use revm_interpreter::Interpreter;
    use revm_primitives::{address, AccountInfo, Bytecode, TransactTo, U256};
    use std::sync::Arc;

    #[test]
    fn test_set_get() {
        let ctx = InstructionsContext::default();
        let key = "my-key";
        let value = vec![0x01, 0x02];

        ctx.set_named_variable(key, value.clone());

        let cloned_ctx = ctx.clone();
        assert_eq!(cloned_ctx.get_named_variable(key).unwrap(), value);
    }

    #[test]
    fn test_context_variables_are_available_during_tx() {
        let code = Bytecode::new_raw([0xEE, 0xEF, 0x00].into());
        let code_hash = code.hash_slow();
        let to_addr = address!("ffffffffffffffffffffffffffffffffffffffff");

        // initialize the custom context and make sure it's None for a given key
        let custom_context = InstructionsContext::default();
        let key = "my-key";
        assert_eq!(custom_context.get_named_variable(key), None);

        let to_capture_instructions = custom_context.clone();
        let to_capture_post_execution = custom_context.clone();
        let mut evm = Evm::builder()
            .with_db(InMemoryDB::default())
            .modify_db(|db| {
                db.insert_account_info(to_addr, AccountInfo::new(U256::ZERO, 0, code_hash, code))
            })
            .modify_tx_env(|tx| tx.transact_to = TransactTo::Call(to_addr))
            .append_handler_register_box(Box::new(move |handler| {
                let writer_context = to_capture_instructions.clone();
                let writer_instruction = Box::new(
                    move |_interp: &mut Interpreter, _host: &mut Evm<'_, (), InMemoryDB>| {
                        // write into the context variable.
                        writer_context.set_named_variable(key, vec![0x01, 0x02]);
                    },
                );
                let reader_context = to_capture_instructions.clone();
                let reader_instruction = Box::new(
                    move |_interp: &mut Interpreter, _host: &mut Evm<'_, (), InMemoryDB>| {
                        // read from context variable and clear.
                        assert_eq!(
                            reader_context.get_named_variable(key).unwrap(),
                            vec![0x01, 0x02]
                        );
                    },
                );

                let mut table = handler.take_instruction_table();
                table = table.map(|mut table| {
                    table.insert_boxed(0xEE, writer_instruction);
                    table.insert_boxed(0xEF, reader_instruction);
                    table
                });
                handler.instruction_table = table;
            }))
            .append_handler_register_box(Box::new(move |handler| {
                let ctx = to_capture_post_execution.clone();
                handler.post_execution.end = Arc::new(move |_, outcome: _| {
                    ctx.clear();
                    outcome
                });
            }))
            .build();

        let _result_and_state = evm.transact().unwrap();

        // ensure the custom context was cleared
        assert_eq!(custom_context.get_named_variable(key), None);
    }
}
