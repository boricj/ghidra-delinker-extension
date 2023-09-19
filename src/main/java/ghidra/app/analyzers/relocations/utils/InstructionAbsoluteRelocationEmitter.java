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
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

public class InstructionAbsoluteRelocationEmitter implements InstructionRelocationEmitter {
	private final Program program;
	private final RelocationTable relocationTable;

	public InstructionAbsoluteRelocationEmitter(Program program, AddressSetView set,
			RelocationTable relocationTable) {
		this.program = program;
		this.relocationTable = relocationTable;
	}

	@Override
	public boolean processInstruction(Function function, Instruction instruction)
			throws MemoryAccessException {
		ReferenceManager referenceManager = program.getReferenceManager();
		Address fromAddress = instruction.getAddress();

		boolean foundRelocation = false;
		for (Reference reference : referenceManager.getReferencesFrom(fromAddress)) {
			if (!isReferenceInteresting(reference)) {
				continue;
			}

			Address toAddress = reference.getToAddress();

			for (int opIdx = 0; opIdx < instruction.getNumOperands(); opIdx++) {
				SymbolWithOffset symbol = SymbolWithOffset.get(program, reference);
				if (symbol == null) {
					continue;
				}

				OperandValueRaw opValue = getOperandValueRaw(instruction, opIdx);
				if (opValue == null) {
					continue;
				}

				if (opValue.unsignedValue == toAddress.getOffset()) {
					foundRelocation = true;
					relocationTable.addAbsolute(fromAddress.add(opValue.offset), opValue.length,
						symbol.name, symbol.offset);
				}
			}
		}

		return foundRelocation;
	}
}
