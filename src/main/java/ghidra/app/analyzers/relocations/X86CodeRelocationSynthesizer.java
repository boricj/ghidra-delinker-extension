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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.commons.lang3.ArrayUtils;

import ghidra.app.analyzers.relocations.utils.InstructionAbsoluteRelocationEmitter;
import ghidra.app.analyzers.relocations.utils.InstructionRelativeRelocationEmitter;
import ghidra.app.analyzers.relocations.utils.InstructionRelocationEmitter;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Mask;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.relocobj.CodeRelocationSynthesizer;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.program.model.symbol.ReferenceManager;

public class X86CodeRelocationSynthesizer implements CodeRelocationSynthesizer {
	private static class X86InstructionAbsoluteRelocationEmitter
			extends InstructionAbsoluteRelocationEmitter {
		private static final List<Byte> OPMASK_MOD_RM_EA_4BYTES =
			Arrays.asList(new Byte[] { 0x07, -1, -1, -1, -1 });
		private static final List<Byte> OPMASK_SIB_4BYTES =
			Arrays.asList(new Byte[] { -8, -1, -1, -1, -1 });

		public X86InstructionAbsoluteRelocationEmitter(Program program, AddressSetView set,
				RelocationTable relocationTable) {
			super(program, set, relocationTable);
		}

		@Override
		public OperandValueRaw getOperandValueRaw(Instruction instruction, int opIdx)
				throws MemoryAccessException {
			OperandValueRaw opValue = super.getOperandValueRaw(instruction, opIdx);
			if (opValue != null) {
				return opValue;
			}

			int opType = instruction.getOperandType(opIdx);
			InstructionPrototype prototype = instruction.getPrototype();
			Mask valueMask = prototype.getOperandValueMask(opIdx);
			byte[] maskBytes = valueMask.getBytes();

			if (OperandType.isAddress(opType)) {
				List<Byte> maskList = Arrays.asList(ArrayUtils.toObject(maskBytes));
				int index;

				index = Collections.indexOfSubList(maskList, OPMASK_MOD_RM_EA_4BYTES);
				if (index != -1) {
					return new OperandValueRaw(instruction, index + 1, 4);
				}

				index = Collections.indexOfSubList(maskList, OPMASK_SIB_4BYTES);
				if (index != -1) {
					return new OperandValueRaw(instruction, index + 1, 4);
				}
			}

			return opValue;
		}
	}

	private static class X86InstructionRelativeRelocationEmitter
			extends InstructionRelativeRelocationEmitter {
		public X86InstructionRelativeRelocationEmitter(Program program, AddressSetView set,
				RelocationTable relocationTable) {
			super(program, set, relocationTable);
		}

		@Override
		public long getReferenceOffset(Instruction instruction) throws MemoryAccessException {
			return instruction.getBytes().length;
		}

		@Override
		public long getAddendOffset(Instruction instruction) throws MemoryAccessException {
			return instruction.getBytes().length - 1;
		}
	}

	@Override
	public void processFunction(Program program, AddressSetView set, Function function,
			RelocationTable relocationTable, MessageLog log) throws MemoryAccessException {
		ReferenceManager referenceManager = program.getReferenceManager();

		InstructionRelocationEmitter absolute =
			new X86InstructionAbsoluteRelocationEmitter(program, set, relocationTable);
		InstructionRelocationEmitter relative =
			new X86InstructionRelativeRelocationEmitter(program, set, relocationTable);

		for (Instruction instruction : program.getListing()
				.getInstructions(function.getBody(), true)) {
			Address fromAddress = instruction.getAddress();
			boolean foundRelocation = false;
			boolean isReferenceInteresting =
				Arrays.stream(referenceManager.getReferencesFrom(fromAddress))
						.anyMatch(r -> absolute.isReferenceInteresting(r) |
							relative.isReferenceInteresting(r));

			foundRelocation |= absolute.processInstruction(function, instruction);
			foundRelocation |= relative.processInstruction(function, instruction);

			if (isReferenceInteresting && !foundRelocation) {
				log.appendMsg(fromAddress.toString(),
					"No relocation emitted for instruction with interesting primary reference.");
			}
		}
	}

	@Override
	public boolean canAnalyze(Program program) {
		// Check language
		Processor processor = program.getLanguage().getProcessor();
		return processor.equals(Processor.findOrPossiblyCreateProcessor("x86"));
	}
}
