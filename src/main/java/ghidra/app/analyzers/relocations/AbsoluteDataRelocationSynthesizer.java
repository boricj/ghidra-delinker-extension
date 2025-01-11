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

import ghidra.app.analyzers.relocations.synthesizers.DataRelocationSynthesizer;
import ghidra.app.analyzers.relocations.utils.SymbolWithOffset;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.util.task.TaskMonitor;

public class AbsoluteDataRelocationSynthesizer implements DataRelocationSynthesizer {
	public AbsoluteDataRelocationSynthesizer() {
	}

	@Override
	public void process(Program program, AddressSetView relocatable, Data pointer,
			RelocationTable relocationTable, TaskMonitor monitor, MessageLog log)
			throws MemoryAccessException {
		if (!pointer.isInitializedMemory()) {
			return;
		}

		Address fromAddress = pointer.getAddress();
		Address toAddress = (Address) pointer.getValue();

		SymbolWithOffset symbolWithOffset =
			SymbolWithOffset.get(pointer.getProgram(), fromAddress, toAddress);
		if (symbolWithOffset != null) {
			relocationTable.addAbsolute(fromAddress, pointer.getLength(), symbolWithOffset.name,
				symbolWithOffset.offset);
		}
	}

	@Override
	public boolean canAnalyze(Program program) {
		return true;
	}
}
