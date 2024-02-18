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

import java.util.List;

import ghidra.app.analyzers.relocations.utils.SymbolWithOffset;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramUtilities;
import ghidra.util.DataConverter;

public class SymbolRelativeInstructionRelocationEmitter
		extends InstructionRelocationEmitter {
	protected final Symbol fromSymbol;

	public SymbolRelativeInstructionRelocationEmitter(Program program,
			RelocationTable relocationTable,
			Function function, Symbol fromSymbol) {
		super(program, relocationTable, function);

		this.fromSymbol = fromSymbol;
	}

	@Override
	public long computeValue(Instruction instruction, int operandIndex, Reference reference,
			int offset, List<Byte> mask) throws MemoryAccessException {
		DataConverter dc = ProgramUtilities.getDataConverter(instruction.getProgram());
		return dc.getSignedValue(instruction.getBytes(), offset, getSizeFromMask(mask));
	}

	@Override
	public boolean matches(Instruction instruction, int operandIndex, Reference reference,
			int offset, List<Byte> mask) throws MemoryAccessException {
		long origin = fromSymbol.getAddress().getUnsignedOffset();
		long relative = computeValue(instruction, operandIndex, reference, offset, mask);
		long target = reference.getToAddress().getUnsignedOffset();

		return origin + relative == target;
	}

	@Override
	public long computeAddend(Instruction instruction, int operandIndex, SymbolWithOffset symbol,
			Reference reference, int offset, List<Byte> mask) throws MemoryAccessException {
		return symbol.offset;
	}

	@Override
	public boolean emitRelocation(Instruction instruction, int operandIndex,
			SymbolWithOffset symbol, Reference reference, int offset, List<Byte> mask, long addend)
			throws MemoryAccessException {
		RelocationTable relocationTable = getRelocationTable();
		Address fromAddress = instruction.getAddress();

		relocationTable.addRelativeSymbol(fromAddress.add(offset), getSizeFromMask(mask),
			symbol.name, addend, fromSymbol.getName());
		return true;
	}
}
