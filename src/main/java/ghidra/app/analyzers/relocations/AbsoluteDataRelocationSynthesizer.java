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

import ghidra.app.analyzers.RelocationTableSynthesizerAnalyzer;
import ghidra.app.analyzers.relocations.synthesizers.DataRelocationSynthesizer;
import ghidra.app.analyzers.relocations.utils.RelocationTarget;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.util.task.TaskMonitor;

public class AbsoluteDataRelocationSynthesizer implements DataRelocationSynthesizer {
	public AbsoluteDataRelocationSynthesizer() {
	}

	@Override
	public boolean process(RelocationTableSynthesizerAnalyzer analyzer, Data pointer,
			TaskMonitor monitor, MessageLog log) throws MemoryAccessException {
		if (!pointer.isInitializedMemory()) {
			return true;
		}

		RelocationTable relocationTable = analyzer.getRelocationTable();
		Address fromAddress = pointer.getAddress();
		Address toAddress = (Address) pointer.getValue();

		RelocationTarget target =
			RelocationTarget.find(pointer.getProgram(), fromAddress, toAddress);
		if (target != null) {
			RelocationTarget finalTarget = analyzer.getFinalRelocationTarget(target);

			relocationTable.addAbsolute(fromAddress, pointer.getLength(),
				finalTarget.getDestination(), finalTarget.getOffset());

			return true;
		}

		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return true;
	}
}
