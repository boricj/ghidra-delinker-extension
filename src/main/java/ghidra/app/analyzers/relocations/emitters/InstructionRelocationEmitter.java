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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.commons.lang3.ArrayUtils;

import ghidra.app.analyzers.relocations.utils.SymbolWithOffset;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Mask;
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
	public final static List<List<Byte>> MASKS_ALLONES = List.of(
		Arrays.asList(new Byte[] { -1, -1, -1, -1, -1, -1, -1, -1 }),
		Arrays.asList(new Byte[] { -1, -1, -1, -1, -1, -1, -1 }),
		Arrays.asList(new Byte[] { -1, -1, -1, -1, -1, -1 }),
		Arrays.asList(new Byte[] { -1, -1, -1, -1, -1 }),
		Arrays.asList(new Byte[] { -1, -1, -1, -1 }),
		Arrays.asList(new Byte[] { -1, -1, -1 }),
		Arrays.asList(new Byte[] { -1, -1 }),
		Arrays.asList(new Byte[] { -1 }));

	private final Program program;
	private final RelocationTable relocationTable;
	private final Function function;

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

	public Program getProgram() {
		return program;
	}

	public RelocationTable getRelocationTable() {
		return relocationTable;
	}

	public Function getFunction() {
		return function;
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

			for (int opIndex = 0; opIndex < instruction.getNumOperands(); opIndex++) {
				foundRelocation |=
					processInstructionOperand(instruction, opIndex, symbol, reference);
			}
		}

		return foundRelocation;
	}

	public boolean processInstructionOperand(Instruction instruction, int operandIndex,
			SymbolWithOffset symbol, Reference reference) throws MemoryAccessException {
		List<Byte> operandValueMask = getOperandValueMask(instruction, operandIndex);

		for (List<Byte> mask : getMasks()) {
			int offset = indexOfMask(operandValueMask, mask);
			if (offset == -1) {
				continue;
			}

			if (!matches(instruction, operandIndex, reference, offset, mask)) {
				continue;
			}

			long addend = computeAddend(instruction, operandIndex, symbol, reference, offset, mask);
			return emitRelocation(instruction, operandIndex, symbol, reference, offset, mask,
				addend);
		}

		return false;
	}

	public int indexOfMask(List<Byte> instructionOperandMask, List<Byte> operandMask) {
		int offset = Collections.indexOfSubList(instructionOperandMask, operandMask);

		if (offset != -1) {
			// Check that every byte before the mask are zeroes.
			for (int index = 0; index < offset; index++) {
				if (instructionOperandMask.get(index) != 0x00) {
					return -1;
				}
			}

			// Check that every byte after the mask are zeroes.
			final int size = instructionOperandMask.size();
			for (int index = offset + operandMask.size(); index < size; index++) {
				if (instructionOperandMask.get(index) != 0x00) {
					return -1;
				}
			}
		}

		return offset;
	}

	public List<List<Byte>> getMasks() {
		return MASKS_ALLONES;
	}

	public int getSizeFromMask(List<Byte> mask) {
		return mask.size();
	}

	public abstract long computeValue(Instruction instruction, int operandIndex,
			Reference reference,
			int offset, List<Byte> mask) throws MemoryAccessException;

	public abstract boolean matches(Instruction instruction, int operandIndex, Reference reference,
			int offset, List<Byte> mask) throws MemoryAccessException;

	public abstract long computeAddend(Instruction instruction, int operandIndex,
			SymbolWithOffset symbol, Reference reference, int offset, List<Byte> mask)
			throws MemoryAccessException;

	public abstract boolean emitRelocation(Instruction instruction, int operandIndex,
			SymbolWithOffset symbol, Reference reference, int offset, List<Byte> mask, long addend)
			throws MemoryAccessException;

	private static List<Byte> getOperandValueMask(Instruction instruction, int operandIndex) {
		InstructionPrototype prototype = instruction.getPrototype();
		Mask valueMask = prototype.getOperandValueMask(operandIndex);
		return Arrays.asList(ArrayUtils.toObject(valueMask.getBytes()));
	}
}
