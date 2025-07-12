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

import java.util.Collection;
import java.util.Optional;

import ghidra.app.analyzers.RelocationTableSynthesizerAnalyzer;
import ghidra.app.analyzers.relocations.patterns.OperandMatch;
import ghidra.app.analyzers.relocations.patterns.OperandMatcher;
import ghidra.app.analyzers.relocations.utils.EvaluationReporter;
import ghidra.app.analyzers.relocations.utils.RelocationTarget;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TaskMonitor;

/**
 * This class streamlines the processing of relocations that fit within one
 * single instruction.
 * 
 * The bulk of the logic for figuring out automatically where the operand is in
 * the instruction is taken care of by this class, so that child classes merely
 * need to emit the relocation itself and provide the target address
 * computation as well (false positives need to be discarded).
 */
public abstract class InstructionRelocationEmitter implements FunctionInstructionSink {
	private final RelocationTableSynthesizerAnalyzer analyzer;
	private final Program program;
	private final RelocationTable relocationTable;
	private final Function function;
	private final EvaluationReporter evaluationReporter;
	private final TaskMonitor monitor;
	private final MessageLog log;

	public InstructionRelocationEmitter(RelocationTableSynthesizerAnalyzer analyzer,
			Function function, EvaluationReporter evaluationRepoter, TaskMonitor monitor,
			MessageLog log) {
		this.analyzer = analyzer;
		this.program = analyzer.getProgram();
		this.relocationTable = analyzer.getRelocationTable();
		this.function = function;
		this.evaluationReporter = evaluationRepoter;
		this.monitor = monitor;
		this.log = log;
	}

	public RelocationTableSynthesizerAnalyzer getAnalyzer() {
		return analyzer;
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
	public boolean process(Instruction instruction) throws MemoryAccessException {
		ReferenceManager referenceManager = program.getReferenceManager();
		Address fromAddress = instruction.getAddress();
		boolean foundRelocation = false;

		for (Reference reference : referenceManager.getReferencesFrom(fromAddress)) {
			if (!isReferenceInteresting(reference, analyzer)) {
				continue;
			}
			RelocationTarget target = RelocationTarget.get(program, reference);
			if (target == null) {
				continue;
			}

			for (int opIndex = 0; opIndex < instruction.getNumOperands(); opIndex++) {
				foundRelocation |=
					processInstructionOperand(instruction, opIndex, target, reference);
			}
		}

		return foundRelocation;
	}

	private boolean processInstructionOperand(Instruction instruction, int operandIndex,
			RelocationTarget target, Reference reference) throws MemoryAccessException {
		boolean emitted = false;

		for (OperandMatcher matcher : getOperandMatchers()) {
			Optional<OperandMatch> opMatch = matcher.match(instruction, operandIndex);

			if (opMatch.isEmpty()) {
				continue;
			}

			OperandMatch operandMatch = opMatch.get();
			if (evaluate(instruction, operandMatch, target, reference)) {
				RelocationTarget finalTarget = analyzer.getFinalRelocationTarget(target);

				emit(instruction, operandMatch, finalTarget, reference);
				emitted = true;
			}
		}

		return emitted;
	}

	protected void reportEvaluation(String type, boolean result, long destination, String format,
			Object... args) {
		evaluationReporter.add(type, result, destination, format, args);
	}

	public abstract Collection<OperandMatcher> getOperandMatchers();

	public abstract boolean evaluate(Instruction instruction, OperandMatch match,
			RelocationTarget target, Reference reference)
			throws MemoryAccessException;

	protected abstract void emit(Instruction instruction, OperandMatch match,
			RelocationTarget target, Reference reference);
}
