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
package ghidra.app.analyzers.relocations.synthesizers;

import java.util.Arrays;
import java.util.List;

import ghidra.app.analyzers.RelocationTableSynthesizerAnalyzer;
import ghidra.app.analyzers.relocations.emitters.FunctionInstructionSink;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class adapts function instruction sinks as a code relocation synthesizer.
 */
public abstract class FunctionInstructionSinkCodeRelocationSynthesizer
		implements CodeRelocationSynthesizer {
	@Override
	public void process(RelocationTableSynthesizerAnalyzer analyzer, Function function,
			TaskMonitor monitor, MessageLog log) throws MemoryAccessException, CancelledException {
		Program program = function.getProgram();
		ReferenceManager referenceManager = program.getReferenceManager();
		Listing listing = program.getListing();
		List<FunctionInstructionSink> sinks =
			getFunctionInstructionSinks(analyzer, function, monitor, log);

		for (Instruction instruction : listing.getInstructions(function.getBody(), true)) {
			Address fromAddress = instruction.getAddress();
			Reference references[] = referenceManager.getReferencesFrom(fromAddress);

			boolean interestingReference = Arrays.stream(references)
					.anyMatch(r -> sinks.stream()
							.anyMatch(s -> s.isReferenceInteresting(r, analyzer)));
			boolean foundRelocation = false;
			for (FunctionInstructionSink sink : sinks) {
				foundRelocation |= sink.process(instruction);
			}

			if (interestingReference && !foundRelocation) {
				log.appendMsg(fromAddress.toString(),
					"No relocation emitted for instruction with interesting primary reference.");
			}
		}
	}

	public abstract List<FunctionInstructionSink> getFunctionInstructionSinks(
			RelocationTableSynthesizerAnalyzer analyzer, Function function, TaskMonitor monitor,
			MessageLog log) throws CancelledException;
}
