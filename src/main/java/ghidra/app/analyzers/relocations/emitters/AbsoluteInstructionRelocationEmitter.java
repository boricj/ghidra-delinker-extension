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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.program.model.symbol.Reference;

public class AbsoluteInstructionRelocationEmitter extends InstructionRelocationEmitter {
	public AbsoluteInstructionRelocationEmitter(Program program, RelocationTable relocationTable,
			Function function) {
		super(program, relocationTable, function);
	}

	@Override
	public long computeTargetAddress(Instruction instruction, Reference reference,
			OperandValueRaw opValue) throws MemoryAccessException {
		return opValue.unsignedValue + getReferenceAddend(instruction);
	}

	@Override
	public boolean emitRelocation(Instruction instruction, Reference reference,
			OperandValueRaw opValue, SymbolWithOffset symbol) throws MemoryAccessException {
		Address fromAddress = reference.getFromAddress();

		relocationTable.addAbsolute(fromAddress.add(opValue.offset), opValue.length, symbol.name,
			symbol.offset);
		return true;
	}
}
