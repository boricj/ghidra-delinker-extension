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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

public class ExecutionContext {
	public interface ExecutionInterpreter {
		public void step(Instruction instruction, ExecutionContext context)
				throws MemoryAccessException;

		public void evaluateTrace(Reference reference, List<Instruction> trace,
				ExecutionContext context) throws MemoryAccessException;
	}

	private final Map<Address, List<Instruction>> instructionToParents = new HashMap<>();
	private final Map<Register, Instruction> registerOutputToLastInstruction = new HashMap<>();

	private final Program program;
	private final MessageLog log;

	public ExecutionContext(Program program, MessageLog log) {
		this.program = program;
		this.log = log;
	}

	public Program getProgram() {
		return program;
	}

	public MessageLog getLog() {
		return log;
	}

	public void run(InstructionIterator iterator, ExecutionInterpreter interpreter)
			throws MemoryAccessException {
		for (Instruction instruction : iterator) {
			interpreter.step(instruction, this);

			Address fromAddress = instruction.getAddress();
			ReferenceManager referenceManager = program.getReferenceManager();

			for (Reference reference : referenceManager.getReferencesFrom(fromAddress)) {
				if (reference.isStackReference()) {
					continue;
				}

				for (List<Instruction> trace : generateTraces(instruction, reference)) {
					interpreter.evaluateTrace(reference, trace, this);
				}
			}
		}
	}

	public void put(Instruction instruction, Register output, List<Register> inputs) {
		List<Instruction> parentInstructions = registerOutputToLastInstruction.entrySet()
				.stream()
				.filter(e -> inputs.contains(e.getKey()))
				.map(e -> e.getValue())
				.collect(Collectors.toList());

		instructionToParents.put(instruction.getAddress(), parentInstructions);
		registerOutputToLastInstruction.put(output, instruction);
	}

	public void remove(Register register) {
		registerOutputToLastInstruction.remove(register);
	}

	private List<List<Instruction>> generateTraces(Instruction instruction, Reference reference) {
		List<List<Instruction>> traces = new ArrayList<>();

		for (int index = 0; index < instruction.getNumOperands(); index++) {
			for (Object operand : instruction.getOpObjects(index)) {
				if (operand instanceof Register) {
					Instruction parent =
						registerOutputToLastInstruction.getOrDefault(operand, null);
					if (parent != null) {
						generateTraces(traces, List.of(instruction), parent);
					}
				}
			}
		}

		if (traces.isEmpty()) {
			traces.add(List.of(instruction));
		}

		return traces;
	}

	private void generateTraces(List<List<Instruction>> traces, List<Instruction> currentTrace,
			Instruction instruction) {
		List<Instruction> newTrace = new ArrayList<>(currentTrace);
		newTrace.add(instruction);

		List<Instruction> parents =
			instructionToParents.getOrDefault(instruction.getAddress(), Collections.emptyList());
		if (parents.isEmpty()) {
			// Trace is built up in reverse order.
			Collections.reverse(newTrace);
			traces.add(newTrace);
		}
		else {
			for (Instruction parentInstruction : parents) {
				generateTraces(traces, newTrace, parentInstruction);
			}
		}
	}
}
