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
package ghidra.app.analyzers.relocations.utils;

import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Mask;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.util.DataConverter;

public interface InstructionRelocationEmitter {
	public static class OperandValueRaw {
		int offset;
		int length;
		long signedValue;
		long unsignedValue;

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

	public default boolean isReferenceInteresting(Reference reference) {
		boolean interesting = true;
		interesting &= reference.isPrimary() && !reference.isStackReference() &&
			!reference.isRegisterReference();
		return interesting;
	}

	public default OperandValueRaw getOperandValueRaw(Instruction instruction, int opIdx)
			throws MemoryAccessException {
		int opType = instruction.getOperandType(opIdx);
		if (!OperandType.isAddress(opType)) {
			return null;
		}

		InstructionPrototype prototype = instruction.getPrototype();
		Mask valueMask = prototype.getOperandValueMask(opIdx);
		byte[] maskBytes = valueMask.getBytes();

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

	public boolean processInstruction(Function function, Instruction instruction)
			throws MemoryAccessException;
}
