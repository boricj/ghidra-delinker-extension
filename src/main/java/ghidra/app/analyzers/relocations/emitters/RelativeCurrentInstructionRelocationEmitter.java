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

import ghidra.app.analyzers.RelocationTableSynthesizerAnalyzer;
import ghidra.app.analyzers.relocations.patterns.OperandMatch;
import ghidra.app.analyzers.relocations.utils.RelocationTarget;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

public abstract class RelativeCurrentInstructionRelocationEmitter
		extends InstructionRelocationEmitter {
	public RelativeCurrentInstructionRelocationEmitter(RelocationTableSynthesizerAnalyzer analyzer,
			Function function, TaskMonitor monitor, MessageLog log) {
		super(analyzer, function, monitor, log);
	}

	@Override
	public boolean evaluate(Instruction instruction, OperandMatch match,
			RelocationTarget target, Reference reference)
			throws MemoryAccessException {
		Address fromAddress = instruction.getAddress();
		long destination = reference.getToAddress().getUnsignedOffset();

		return destination == fromAddress.getUnsignedOffset() + match.getValue();
	}

	@Override
	public void emit(Instruction instruction, OperandMatch match, RelocationTarget target,
			Reference reference) {
		RelocationTable relocationTable = getRelocationTable();
		Address address = instruction.getAddress().add(match.getOffset());
		long addend = address.getUnsignedOffset() - target.getAddress().getUnsignedOffset() +
			match.getValue();

		relocationTable.addRelativePC(address, match.getSize(), match.getBitmask(),
			target.getDestination(), addend);
	}
}
