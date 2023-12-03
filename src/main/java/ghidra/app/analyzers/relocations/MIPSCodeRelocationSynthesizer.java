/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.analyzers.relocations;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidra.app.analyzers.relocations.utils.ExecutionContext;
import ghidra.app.analyzers.relocations.utils.ExecutionContext.ExecutionInterpreter;
import ghidra.app.analyzers.relocations.utils.SymbolWithOffset;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.relocobj.CodeRelocationSynthesizer;
import ghidra.program.model.relocobj.RelocationHighPair;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.DataConverter;

public class MIPSCodeRelocationSynthesizer implements CodeRelocationSynthesizer {
	public static class MIPSExecutionInterpreter implements ExecutionInterpreter {
		private final List<Register> registersToRemove = new ArrayList<>();

		private final Program program;
		private final DataConverter dc;
		private final MessageLog log;
		private final RelocationTable relocationTable;
		private final Symbol gp;

		public MIPSExecutionInterpreter(Program program, MessageLog log) {
			this.program = program;
			this.dc = DataConverter.getInstance(program.getLanguage().isBigEndian());
			this.log = log;
			this.relocationTable = RelocationTable.get(program);

			SymbolIterator it = program.getSymbolTable().getSymbols("_gp");
			this.gp = it.hasNext() ? it.next() : null;
		}

		@Override
		public void step(Instruction instruction, ExecutionContext context)
				throws MemoryAccessException {
			for (Register register : registersToRemove) {
				context.remove(register);
			}
			registersToRemove.clear();

			switch (instruction.getMnemonicString()) {
				case "lui":
					execute_lui(instruction, context);
					break;
				case "_addiu":
				case "addiu":
					execute_addiu(instruction, context);
					break;
				case "lb":
				case "lbu":
				case "lh":
				case "lhu":
				case "lw":
					execute_load(instruction, context);
					break;
				case "sb":
				case "sh":
				case "sw":
					break;
				case "addu":
				case "or":
					execute_rformat(instruction, context);
					break;
				default:
					execute_other(instruction, context);
					break;
			}
		}

		private void execute_lui(Instruction instruction, ExecutionContext context) {
			Register output = (Register) instruction.getOpObjects(0)[0];
			context.put(instruction, output, Collections.emptyList());
		}

		private void execute_addiu(Instruction instruction, ExecutionContext context)
				throws MemoryAccessException {
			Register output = (Register) instruction.getOpObjects(0)[0];
			Register input = (Register) instruction.getOpObjects(1)[0];

			context.put(instruction, output, List.of(input));

			// If gp is initialized, remove from context on next step.
			if (output.getName().equals("gp")) {
				registersToRemove.add(output);
			}
		}

		private void execute_load(Instruction instruction, ExecutionContext context)
				throws MemoryAccessException {
			Register output = (Register) instruction.getOpObjects(0)[0];
			Register input = (Register) instruction.getOpObjects(1)[1];

			context.put(instruction, output, List.of(input));
			context.remove(output);
		}

		private void execute_rformat(Instruction instruction, ExecutionContext context)
				throws MemoryAccessException {
			Register output = (Register) instruction.getOpObjects(0)[0];
			Register input1 = (Register) instruction.getOpObjects(1)[0];
			Register input2 = (Register) instruction.getOpObjects(2)[0];

			context.put(instruction, output, List.of(input1, input2));
		}

		private void execute_other(Instruction instruction, ExecutionContext context)
				throws MemoryAccessException {
			if (instruction.getNumOperands() == 3) {
				int op0 = instruction.getOperandType(0);
				int op1 = instruction.getOperandType(1);
				int op2 = instruction.getOperandType(2);

				if ((op0 & OperandType.REGISTER) != 0 && (op1 & OperandType.REGISTER) != 0 &&
					(op2 & (OperandType.REGISTER | OperandType.SCALAR)) != 0) {
					Register output = (Register) instruction.getOpObjects(0)[0];
					context.remove(output);
				}
			}
		}

		private Long buildAddress(SymbolWithOffset symbol, Reference reference,
				Instruction mipsHi16, Instruction mipsLo16, Instruction mips26)
				throws MemoryAccessException {
			String originator = reference.getFromAddress().toString();
			String msg = null;

			Long address = null;

			if (mipsHi16 != null && mipsLo16 != null) {
				address = (dc.getInt(mipsHi16.getBytes()) << 16) & 0xffffffffL;
				address += (short) dc.getInt(mipsLo16.getBytes());
			}
			else if (mipsHi16 == null && mipsLo16 != null && gp != null) {
				address = gp.getAddress().getOffset();
				address += (short) dc.getInt(mipsLo16.getBytes());
			}
			else if (mips26 != null) {
				address = (reference.getFromAddress().getOffset() + 4) & 0xf0000000L;
				address |= (dc.getInt(mips26.getBytes()) & 0x3ffffff) << 2;
			}

			if (address == null) {
				return null;
			}
			else if (address != (symbol.address + symbol.offset)) {
				//				msg = String.format(
				//					"Address 0x%x recovered from instructions doesn't match address 0x%x+%d recovered from reference %s",
				//					address, symbol.address, symbol.offset, reference);
				//				log.appendMsg(originator, msg);
				return null;
			}
			else if (mipsLo16 != null && (symbol.offset > 0x7fff)) {
				msg = String.format(
					"Addend in address 0x%x+%d exceeds 32767 for reference %s (not yet implemented)",
					symbol.address, symbol.offset, reference);
				log.appendMsg(originator, msg);
				return null;
			}
			else {
				return address;
			}
		}

		@Override
		public void evaluateTrace(Reference reference, List<Instruction> trace,
				ExecutionContext context) throws MemoryAccessException {
			String originator = reference.getFromAddress().toString();
			String msg = null;

			SymbolWithOffset symbol = SymbolWithOffset.get(program, reference);
			if (symbol == null) {
				msg = String.format("Couldn't find symbol for reference %s", reference);
				log.appendMsg(originator, msg);
				return;
			}

			Instruction mipsHi16 = null;
			Instruction mipsLo16 = null;
			Instruction mips26 = null;

			for (Instruction instruction : trace) {
				switch (instruction.getMnemonicString()) {
					case "lui":
						mipsHi16 = instruction;
						break;
					case "_addiu":
					case "addiu":
					case "lb":
					case "lbu":
					case "lh":
					case "lhu":
					case "lw":
					case "sb":
					case "sh":
					case "sw":
						if (mipsLo16 == null) {
							mipsLo16 = instruction;
						}
						break;
					case "j":
					case "jal":
						mips26 = instruction;
						break;
					default:
						break;
				}
			}

			Long builtAddress = buildAddress(symbol, reference, mipsHi16, mipsLo16, mips26);
			if (builtAddress == null) {
				return;
			}

			if (mipsHi16 != null && mipsLo16 != null) {
				RelocationHighPair hiRel =
					relocationTable.addHighPair(mipsHi16.getAddress(), 4, 0xFFFF, symbol.name);
				relocationTable.addLowPair(mipsLo16.getAddress(), 4, 0xFFFF, hiRel, symbol.offset);
			}
			else if (mipsHi16 == null && mipsLo16 != null) {
				relocationTable.addRelativeSymbol(mipsLo16.getAddress(), 4, 0xFFFF, 0, symbol.name,
					symbol.offset, "_gp");
			}
			else if (mips26 != null) {
				relocationTable.addMIPS26(mips26.getAddress(), symbol.name, symbol.offset);
			}
			else {
				throw new RuntimeException(
					"Address synthesized from instructions but instruction pattern not recognized!");
			}
		}
	}

	@Override
	public void processFunction(Program program, AddressSetView set, Function function,
			RelocationTable relocationTable, MessageLog log) throws MemoryAccessException {
		ExecutionContext context = new ExecutionContext(function.getProgram(), log);
		MIPSExecutionInterpreter interpreter =
			new MIPSExecutionInterpreter(function.getProgram(), log);

		context.run(function.getProgram().getListing().getInstructions(function.getBody(), true),
			interpreter);
	}

	@Override
	public boolean canAnalyze(Program program) {
		// Check language
		Processor processor = program.getLanguage().getProcessor();
		return processor.equals(Processor.findOrPossiblyCreateProcessor("MIPS")) ||
			processor.equals(Processor.findOrPossiblyCreateProcessor("PSX"));
	}
}
