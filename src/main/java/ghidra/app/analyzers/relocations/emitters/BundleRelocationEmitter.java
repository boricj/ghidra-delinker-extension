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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.analyzers.relocations.utils.SymbolWithOffset;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
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

		@Override
		public String toString() {
			return String.format("%s> %s", instruction.getAddress(), instruction);
		}

		public String dumpGraph(int indentLevel) {
			String nodeString = "";
			for (int i = 0; i < indentLevel; i++) {
				nodeString += "    ";
			}
			nodeString += this + "\n";

			List<String> childrenStrings =
				children.stream().map(n -> n.dumpGraph(indentLevel + 1)).toList();
			return nodeString + String.join("", childrenStrings);
		}
	}

	private final Program program;
	private final RelocationTable relocationTable;
	private final Function function;
	private final TaskMonitor monitor;
	private final MessageLog log;

	private final CodeBlockModel codeBlockModel;
	private final Map<CodeBlock, Map<Register, Node>> codeBlockRegisterNodes = new HashMap<>();
	private CodeBlock currentCodeBlock;

	public BundleRelocationEmitter(Program program, RelocationTable relocationTable,
			Function function, TaskMonitor monitor, MessageLog log) {
		this.program = program;
		this.relocationTable = relocationTable;
		this.function = function;
		this.monitor = monitor;
		this.log = log;

		this.codeBlockModel = new BasicBlockModel(program);
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
	public boolean process(Instruction instruction, AddressSetView relocatable)
			throws MemoryAccessException, CancelledException {
		Map<Register, Node> registerNodes = getRegisterNodesForInstruction(instruction);
		ReferenceManager referenceManager = program.getReferenceManager();
		Address fromAddress = instruction.getAddress();
		boolean foundRelocation = false;

		for (Reference reference : referenceManager.getReferencesFrom(fromAddress)) {
			if (!isReferenceInteresting(reference, relocatable)) {
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
					.filter(node -> node != null &&
						isInstructionReferenceRelatedToNode(instruction, reference, node))
					.toList();

			Node node = new Node(instruction, null, children);
			try {
				foundRelocation |= evaluateRoot(reference, symbol, node);
			}
			catch (RuntimeException ex) {
				String msg = String.format(
					"Caught exception while processing instruction graph:\n%s", node.dumpGraph(0));
				throw new RuntimeException(msg, ex);
			}
		}

		updateRegisterNodes(instruction, registerNodes);

		return foundRelocation;
	}

	public boolean isInstructionReferenceRelatedToNode(Instruction instruction, Reference reference,
			Node node) {
		return true;
	}

	private void updateRegisterNodes(Instruction instruction, Map<Register, Node> registerNodes) {
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

	private Map<Register, Node> getRegisterNodesForInstruction(Instruction instruction)
			throws CancelledException {
		Address address = instruction.getAddress();

		if (currentCodeBlock == null || !currentCodeBlock.contains(address)) {
			currentCodeBlock = codeBlockModel.getCodeBlockAt(address, monitor);
		}

		if (!codeBlockRegisterNodes.containsKey(currentCodeBlock)) {
			CodeBlock latestPredecessorCodeBlock = findLatestPredecessorCodeBlock(currentCodeBlock);
			Map<Register, Node> latestPredecessorRegisterNodes =
				codeBlockRegisterNodes.get(latestPredecessorCodeBlock);

			if (latestPredecessorRegisterNodes != null) {
				codeBlockRegisterNodes.put(currentCodeBlock,
					new HashMap<>(latestPredecessorRegisterNodes));
			}
			else {
				codeBlockRegisterNodes.put(currentCodeBlock, new HashMap<>());
			}
		}

		return codeBlockRegisterNodes.get(currentCodeBlock);
	}

	private CodeBlock findLatestPredecessorCodeBlock(CodeBlock codeBlock)
			throws CancelledException {
		Address codeBlockAddress = codeBlock.getMinAddress();

		CodeBlock bestCodeBlockCandidate = null;
		CodeBlockReferenceIterator it = codeBlock.getSources(monitor);
		while (it.hasNext()) {
			CodeBlockReference ref = it.next();
			CodeBlock codeBlockCandidate = ref.getSourceBlock();
			Address candidateMaxAddress = codeBlockCandidate.getMaxAddress();

			if (!function.getBody().contains(codeBlockCandidate) ||
				codeBlockCandidate.equals(codeBlock) ||
				candidateMaxAddress.compareTo(codeBlockAddress) >= 0) {
				continue;
			}

			if (bestCodeBlockCandidate == null) {
				bestCodeBlockCandidate = codeBlockCandidate;
				continue;
			}

			if (candidateMaxAddress.compareTo(bestCodeBlockCandidate.getMaxAddress()) > 0) {
				bestCodeBlockCandidate = codeBlockCandidate;
			}
		}

		return bestCodeBlockCandidate;
	}

	public abstract boolean evaluateRoot(Reference reference, SymbolWithOffset symbol, Node node)
			throws MemoryAccessException;
}
