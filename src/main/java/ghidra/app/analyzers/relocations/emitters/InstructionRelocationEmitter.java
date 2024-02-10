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
package ghidra.app.analyzers.relocations.emitters;

import ghidra.app.analyzers.relocations.utils.SymbolWithOffset;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Mask;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.DataConverter;

/**
 * This class streamlines the processing of relocations that fit within one
 * single instruction.
 * 
 * The bulk of the logic for figuring out automatically where the operand is in
 * the instruction is taken care of by this class, so that child classes merely
 * need to emit the relocation itself and provide the target address
 * computation as well (false positives need to be discarded).
 */
public abstract class InstructionRelocationEmitter implements FunctionInstructionSink {
	protected final Program program;
	protected final RelocationTable relocationTable;
	protected final Function function;

	public static class OperandValueRaw {
		public int offset;
		public int length;
		public long signedValue;
		public long unsignedValue;

		public OperandValueRaw(Instruction instruction, int offset, int length)
				throws MemoryAccessException {
			byte[] instructionBytes = instruction.getBytes();
			DataConverter dc =
				DataConverter.getInstance(instruction.getProgram().getLanguage().isBigEndian());

			this.offset = offset;
			this.length = length;
			this.unsignedValue = dc.getValue(instructionBytes, offset, length);
			this.signedValue = dc.getSignedValue(instructionBytes, offset, length);
		}
	}

	public InstructionRelocationEmitter(Program program, RelocationTable relocationTable,
			Function function) {
		this.program = program;
		this.relocationTable = relocationTable;
		this.function = function;
	}

	@Override
	public boolean process(Instruction instruction) throws MemoryAccessException {
		ReferenceManager referenceManager = program.getReferenceManager();
		Address fromAddress = instruction.getAddress();
		boolean foundRelocation = false;

		for (Reference reference : referenceManager.getReferencesFrom(fromAddress)) {
			if (!isReferenceInteresting(reference)) {
				continue;
			}
			SymbolWithOffset symbol = SymbolWithOffset.get(program, reference);
			if (symbol == null) {
				continue;
			}

			Address toAddress = reference.getToAddress();

			for (int opIdx = 0; opIdx < instruction.getNumOperands(); opIdx++) {
				OperandValueRaw opValue = getOperandValueRaw(instruction, opIdx);
				if (opValue == null) {
					continue;
				}

				long target = computeTargetAddress(instruction, reference, opValue);
				if (target == toAddress.getOffset()) {
					foundRelocation |= emitRelocation(instruction, reference, opValue, symbol);
				}
			}
		}

		return foundRelocation;
	}

	public OperandValueRaw getOperandValueRaw(Instruction instruction, int opIdx)
			throws MemoryAccessException {
		int opType = instruction.getOperandType(opIdx);
		if (!OperandType.isAddress(opType)) {
			return null;
		}

		InstructionPrototype prototype = instruction.getPrototype();
		Mask valueMask = prototype.getOperandValueMask(opIdx);
		byte[] maskBytes = valueMask.getBytes();

		// Here, we try to find a continuous range of whole bytes inside the
		// operand mask. Instructions sets with weird masks will need to
		// overload this method to handle special cases.
		int offset = 0;
		int length = 0;
		for (byte maskByte : maskBytes) {
			if (maskByte == 0x00) {
				if (length == 0) {
					offset++;
				}
				else {
					break;
				}
			}
			else if (maskByte == (byte) 0xFF) {
				length++;
			}
			else {
				return null;
			}
		}

		if (length < 1 || length > 8) {
			return null;
		}

		return new OperandValueRaw(instruction, offset, length);
	}

	public long getReferenceAddend(Instruction instruction) throws MemoryAccessException {
		return 0;
	}

	public long getInstructionAddend(Instruction instruction) throws MemoryAccessException {
		return 0;
	}

	public abstract long computeTargetAddress(Instruction instruction, Reference reference,
			OperandValueRaw opValue) throws MemoryAccessException;

	public abstract boolean emitRelocation(Instruction instruction, Reference reference,
			OperandValueRaw opValue, SymbolWithOffset symbol) throws MemoryAccessException;
}
