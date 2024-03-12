use revm::{Database, Evm};
use revm_interpreter::{Instruction, Interpreter};

const CUSTOM_INSTRUCTION_COST: u64 = 133;

/// Type alias for a function pointer that initializes instruction objects.
pub type InstructionInitializer<'a, EXT, DB> = fn() -> InstructionWithOpCode<Evm<'a, EXT, DB>>;

/// Constructs and returns a collection of instruction initializers.
pub fn initializers<'a, EXT, DB: Database>() -> Vec<InstructionInitializer<'a, EXT, DB>> {
    vec![auth::<EXT, DB>, authcall::<EXT, DB>]
}

/// Association of OpCode and correspondent instruction.
#[derive(Clone, Debug)]
pub struct InstructionWithOpCode<H> {
    /// Opcode.
    pub opcode: u8,
    /// Instruction.
    pub instruction: Instruction<H>,
}

fn auth_instruction<EXT, DB: Database>(interp: &mut Interpreter, _evm: &mut Evm<'_, EXT, DB>) {
    interp.gas.record_cost(CUSTOM_INSTRUCTION_COST);
}

/// AUTH's opcode and instruction.
pub fn auth<'a, EXT, DB: Database>() -> InstructionWithOpCode<Evm<'a, EXT, DB>> {
    InstructionWithOpCode { opcode: 0xF6, instruction: auth_instruction::<EXT, DB> }
}

fn authcall_instruction<EXT, DB: Database>(interp: &mut Interpreter, _evm: &mut Evm<'_, EXT, DB>) {
    interp.gas.record_cost(CUSTOM_INSTRUCTION_COST);
}

/// AUTHCALL's opcode and instruction.
pub fn authcall<'a, EXT, DB: Database>() -> InstructionWithOpCode<Evm<'a, EXT, DB>> {
    InstructionWithOpCode { opcode: 0xF7, instruction: authcall_instruction::<EXT, DB> }
}
