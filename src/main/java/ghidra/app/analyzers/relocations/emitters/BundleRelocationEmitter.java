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

import java.util.Arrays;
import java.util.Set;
import java.util.HashSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.analyzers.relocations.utils.SymbolWithOffset;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class streamlines the processing of relocations that span across
 * multiple instructions.
 * 
 * RISC instruction sets generally can't embed a pointer-sized integer constant
 * inside a single instruction. If the compiler didn't use a constant pool,
 * then the pointer is probably loaded across several instructions piecewise,
 * which requires multiple, coordinated relocations to fix up the immediates.
 * 
 * While Ghidra can figure out references from this through symbolic execution,
 * we need to identify the relocation spots that led to this reference, which
 * Ghidra's program model doesn't keep track of. Therefore, we have to figure
 * out that part ourselves.
 */
public abstract class BundleRelocationEmitter implements FunctionInstructionSink {
	public static class Node {
		private final Instruction instruction;
		private final Register output;
		private final List<Node> children;

		public Node(Instruction instruction, Register output, List<Node> children) {
			this.instruction = instruction;
			this.output = output;
			this.children = children;
		}

		public Instruction getInstruction() {
			return instruction;
		}

		public Register getOutput() {
			return output;
		}

		public List<Node> getChildren() {
			return children;
		}
	}

	private final Program program;
	private final RelocationTable relocationTable;
	private final Function function;
	private final TaskMonitor monitor;
	private final MessageLog log;

	private final Map<Register, Node> registerNodes = new HashMap<>();

	public BundleRelocationEmitter(Program program, RelocationTable relocationTable,
			Function function, TaskMonitor monitor, MessageLog log) {
		this.program = program;
		this.relocationTable = relocationTable;
		this.function = function;
		this.monitor = monitor;
		this.log = log;
	}

	public Program getProgram() {
		return program;
	}

	public RelocationTable getRelocationTable() {
		return relocationTable;
	}

	public Function getFunction() {
		return function;
	}

	public TaskMonitor getTaskMonitor() {
		return monitor;
	}

	public MessageLog getMessageLog() {
		return log;
	}

	@Override
	public boolean process(Instruction instruction)
			throws MemoryAccessException, CancelledException {
		ReferenceManager referenceManager = program.getReferenceManager();
		Address fromAddress = instruction.getAddress();
		boolean foundRelocation = false;

		for (Reference reference : referenceManager.getReferencesFrom(fromAddress)) {
			if (!isReferenceInteresting(reference)) {
				continue;
			}
			SymbolWithOffset symbol = SymbolWithOffset.get(program, reference);
			if (symbol == null) {
				continue;
			}

			Set<Object> operands = new HashSet<>();
			operands.addAll(Arrays.asList(instruction.getInputObjects()));
			operands.addAll(Arrays.asList(instruction.getResultObjects()));
			List<Node> children = operands.stream()
					.map(operand -> registerNodes.getOrDefault(operand, null))
					.filter(node -> node != null && isInstructionRelatedToNode(instruction, node))
					.toList();

			Node node = new Node(instruction, null, children);
			foundRelocation |= evaluateRoot(reference, symbol, node);
		}

		updateRegisterNodes(instruction);

		return foundRelocation;
	}

	public boolean isInstructionRelatedToNode(Instruction instruction, Node node) {
		return true;
	}

	private void updateRegisterNodes(Instruction instruction) {
		List<Node> children = Arrays.stream(instruction.getInputObjects())
				.map(o -> registerNodes.getOrDefault(o, null))
				.filter(o -> o != null)
				.toList();
		Map<Register, Node> newOutputRegisterNodes = new HashMap<>();
		for (Object operand : instruction.getResultObjects()) {
			if (operand instanceof Register) {
				Register output = (Register) operand;
				Node node = new Node(instruction, output, children);

				newOutputRegisterNodes.put(output, node);
			}
		}

		registerNodes.putAll(newOutputRegisterNodes);
	}

	public abstract boolean evaluateRoot(Reference reference, SymbolWithOffset symbol, Node node)
			throws MemoryAccessException;
}
