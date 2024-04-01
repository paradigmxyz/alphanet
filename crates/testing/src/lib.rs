//! Alphanet-testing module

#![warn(unused_crate_dependencies)]

#[cfg(test)]
mod tests {

    use alphanet_instructions::{context::InstructionsContext, eip3074};
    use eyre::Result;
    use revm::{Evm, InMemoryDB};
    use revm_primitives::{address, AccountInfo, Bytecode, Bytes, TransactTo, U256};
    use serde_derive::{Deserialize, Serialize};
    use std::{fs, path::Path, sync::Arc};

    #[derive(Serialize, Deserialize, Debug)]
    struct TestData {
        bytecode: TestBytecode,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct TestBytecode {
        object: String,
    }

    fn load_test_data<P: AsRef<Path>>(path: P) -> Result<TestData> {
        let file_contents = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&file_contents)?)
    }

    #[test]
    fn test_eip3074_integration() {
        let test_data = load_test_data("resources/eip3074/out/BaseAuth.sol/BaseAuth.json")
            .expect("could not read test data");

        let raw_bytecode = Bytes::from(test_data.bytecode.object);
        let code = Bytecode::new_raw(raw_bytecode);
        let code_hash = code.hash_slow();
        let to_addr = address!("ffffffffffffffffffffffffffffffffffffffff");

        // initialize the custom context.
        let custom_context = InstructionsContext::default();

        let to_capture_post_execution = custom_context.clone();
        let mut evm = Evm::builder()
            .with_db(InMemoryDB::default())
            .modify_db(|db| {
                db.insert_account_info(to_addr, AccountInfo::new(U256::ZERO, 0, code_hash, code))
            })
            .modify_tx_env(|tx| {
                tx.transact_to = TransactTo::Call(to_addr);
            })
            .append_handler_register_box(Box::new(move |handler| {
                let instructions = eip3074::boxed_instructions(custom_context.clone());
                let mut table = handler.take_instruction_table();
                table = table.map(|mut table| {
                    for instruction in instructions {
                        table.insert_boxed(instruction.opcode, instruction.boxed_instruction);
                    }
                    table
                });
                handler.instruction_table = table;

                let post_execution_context = to_capture_post_execution.clone();
                #[allow(clippy::arc_with_non_send_sync)]
                {
                    handler.post_execution.end = Arc::new(move |_, outcome: _| {
                        post_execution_context.clear();
                        outcome
                    });
                }
            }))
            .build();

        let _result_and_state = evm.transact().unwrap();
    }
}
