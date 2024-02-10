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
import ghidra.program.model.symbol.Symbol;

public abstract class SymbolRelativeInstructionRelocationEmitter
		extends InstructionRelocationEmitter {
	protected final Symbol fromSymbol;

	public SymbolRelativeInstructionRelocationEmitter(Program program,
			RelocationTable relocationTable,
			Function function, Symbol fromSymbol) {
		super(program, relocationTable, function);

		this.fromSymbol = fromSymbol;
	}

	@Override
	public long computeTargetAddress(Instruction instruction, Reference reference,
			OperandValueRaw opValue) throws MemoryAccessException {
		Address fromAddress = fromSymbol.getAddress();

		return fromAddress.getOffset() + opValue.signedValue + getReferenceAddend(instruction);
	}

	@Override
	public boolean emitRelocation(Instruction instruction, Reference reference,
			OperandValueRaw opValue, SymbolWithOffset symbol) throws MemoryAccessException {
		Address fromAddress = instruction.getAddress();

		relocationTable.addRelativeSymbol(fromAddress.add(opValue.offset), opValue.length,
			symbol.name, symbol.offset - getInstructionAddend(instruction), fromSymbol.getName());
		return true;
	}
}
