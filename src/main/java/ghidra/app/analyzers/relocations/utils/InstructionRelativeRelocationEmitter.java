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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

public abstract class InstructionRelativeRelocationEmitter implements InstructionRelocationEmitter {
	private final Program program;
	private final AddressSetView set;
	private final RelocationTable relocationTable;

	public InstructionRelativeRelocationEmitter(Program program, AddressSetView set,
			RelocationTable relocationTable) {
		this.program = program;
		this.set = set;
		this.relocationTable = relocationTable;
	}

	@Override
	public boolean processInstruction(Function function, Instruction instruction)
			throws MemoryAccessException {
		ReferenceManager referenceManager = program.getReferenceManager();
		Address fromAddress = instruction.getAddress();
		AddressRange fromRange = set.getRangeContaining(fromAddress);

		boolean foundRelocation = false;
		for (Reference reference : referenceManager.getReferencesFrom(fromAddress)) {
			if (!isReferenceInteresting(reference)) {
				continue;
			}

			Address toAddress = reference.getToAddress();
			AddressRange toRange = set.getRangeContaining(toAddress);

			for (int opIdx = 0; opIdx < instruction.getNumOperands(); opIdx++) {
				SymbolWithOffset symbol = SymbolWithOffset.get(program, reference);
				if (symbol == null) {
					continue;
				}

				OperandValueRaw opValue = getOperandValueRaw(instruction, opIdx);
				if (opValue == null) {
					continue;
				}

				long extraOffset = getReferenceOffset(instruction);
				long target = fromAddress.getOffset() + opValue.signedValue + extraOffset;
				if (target == toAddress.getOffset()) {
					foundRelocation = true;

					if (!fromRange.equals(toRange)) {
						relocationTable.addRelativePC(fromAddress.add(opValue.offset),
							opValue.length,
							symbol.name, symbol.offset - getAddendOffset(instruction));
					}
				}
			}
		}

		return foundRelocation;
	}

	public abstract long getReferenceOffset(Instruction instruction) throws MemoryAccessException;

	public abstract long getAddendOffset(Instruction instruction) throws MemoryAccessException;
}
