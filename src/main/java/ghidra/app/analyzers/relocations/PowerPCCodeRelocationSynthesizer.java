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

import java.util.Collection;
import java.util.List;

import ghidra.app.analyzers.RelocationTableSynthesizerAnalyzer;
import ghidra.app.analyzers.relocations.emitters.FunctionInstructionSink;
import ghidra.app.analyzers.relocations.emitters.InstructionRelocationEmitter;
import ghidra.app.analyzers.relocations.patterns.FixedOperandMatcher;
import ghidra.app.analyzers.relocations.patterns.OperandMatch;
import ghidra.app.analyzers.relocations.patterns.OperandMatcher;
import ghidra.app.analyzers.relocations.synthesizers.FunctionInstructionSinkCodeRelocationSynthesizer;
import ghidra.app.analyzers.relocations.utils.EvaluationReporter;
import ghidra.app.analyzers.relocations.utils.RelocationTarget;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.relocobj.Relocation;
import ghidra.program.model.relocobj.RelocationHighPair;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.util.ProgramUtilities;
import ghidra.util.DataConverter;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class PowerPCCodeRelocationSynthesizer
		extends FunctionInstructionSinkCodeRelocationSynthesizer {
	private static final long REL24_BITMASK = 0x03fffffcL;
	private static final long REL14_BITMASK = 0x0000fffcL;
	private static final long LO16_BITMASK = 0x0000ffffL;
	private static final long HI16_BITMASK = 0x0000ffffL;

	private static class Rel24OperandMatcher extends FixedOperandMatcher {
		public Rel24OperandMatcher() {
			super(new Byte[] { 0x03, -1, -1, -4 });
		}

		@Override
		public OperandMatch createMatch(Instruction instruction, int operandIndex)
				throws MemoryAccessException {
			DataConverter dc = ProgramUtilities.getDataConverter(instruction.getProgram());
			long value = dc.getInt(instruction.getBytes()) & REL24_BITMASK;

			if ((value & 0x02000000L) != 0) {
				value |= ~0x03ffffffL;
			}

			return new OperandMatch(operandIndex, 0, 4, REL24_BITMASK, value);
		}
	}

	private static class PowerPC_REL24_InstructionRelocationEmitter
			extends InstructionRelocationEmitter {
		private static final OperandMatcher OPERAND_MATCHER = new Rel24OperandMatcher();

		public PowerPC_REL24_InstructionRelocationEmitter(
				RelocationTableSynthesizerAnalyzer analyzer, Function function,
				EvaluationReporter evaluationReporter, TaskMonitor monitor, MessageLog log) {
			super(analyzer, function, evaluationReporter, monitor, log);
		}

		@Override
		public Collection<OperandMatcher> getOperandMatchers() {
			return List.of(OPERAND_MATCHER);
		}

		@Override
		public boolean evaluate(Instruction instruction, OperandMatch match,
				RelocationTarget target, Reference reference) throws MemoryAccessException {
			if (!reference.getReferenceType().isFlow()) {
				return false;
			}

			Address fromAddress = instruction.getAddress();
			long destination = reference.getToAddress().getUnsignedOffset();
			boolean result = destination == fromAddress.getUnsignedOffset() + match.getValue();

			reportEvaluation("PowerPC REL24 flow", result, destination, "0x%08x + %d",
				fromAddress.getUnsignedOffset(), match.getValue());
			return result;
		}

		@Override
		protected void emit(Instruction instruction, OperandMatch match,
				RelocationTarget target, Reference reference) {
			RelocationTable relocationTable = getRelocationTable();
			Address address = instruction.getAddress().add(match.getOffset());
			long addend =
				address.getUnsignedOffset() - target.getAddress().getUnsignedOffset() +
					match.getValue();
			boolean isTransparent = !reference.getReferenceType().isCall();

			relocationTable.addRelativePC(address, match.getSize(), match.getBitmask(),
				target.getDestination(), addend, isTransparent);
		}
	}

	private static class Rel14OperandMatcher extends FixedOperandMatcher {
		public Rel14OperandMatcher() {
			super(new Byte[] { 0x00, 0x00, -1, -4 });
		}

		@Override
		public OperandMatch createMatch(Instruction instruction, int operandIndex)
				throws MemoryAccessException {
			DataConverter dc = ProgramUtilities.getDataConverter(instruction.getProgram());
			long value = dc.getInt(instruction.getBytes()) & REL14_BITMASK;

			if ((value & 0x00008000L) != 0) {
				value |= ~0x0000ffffL;
			}

			return new OperandMatch(operandIndex, 0, 4, REL14_BITMASK, value);
		}
	}

	private static class PowerPC_REL14_InstructionRelocationEmitter
			extends InstructionRelocationEmitter {
		private static final OperandMatcher OPERAND_MATCHER = new Rel14OperandMatcher();

		public PowerPC_REL14_InstructionRelocationEmitter(
				RelocationTableSynthesizerAnalyzer analyzer, Function function,
				EvaluationReporter evaluationReporter, TaskMonitor monitor, MessageLog log) {
			super(analyzer, function, evaluationReporter, monitor, log);
		}

		@Override
		public Collection<OperandMatcher> getOperandMatchers() {
			return List.of(OPERAND_MATCHER);
		}

		@Override
		public boolean evaluate(Instruction instruction, OperandMatch match,
				RelocationTarget target, Reference reference) throws MemoryAccessException {
			if (!reference.getReferenceType().isFlow()) {
				return false;
			}

			Address fromAddress = instruction.getAddress();
			long destination = reference.getToAddress().getUnsignedOffset();
			boolean result = destination == fromAddress.getUnsignedOffset() + match.getValue();

			reportEvaluation("PowerPC REL14 flow", result, destination, "0x%08x + %d",
				fromAddress.getUnsignedOffset(), match.getValue());
			return result;
		}

		@Override
		protected void emit(Instruction instruction, OperandMatch match,
				RelocationTarget target, Reference reference) {
			RelocationTable relocationTable = getRelocationTable();
			Address address = instruction.getAddress().add(match.getOffset());
			long addend =
				address.getUnsignedOffset() - target.getAddress().getUnsignedOffset() +
					match.getValue();
			boolean isTransparent = !reference.getReferenceType().isCall();

			relocationTable.addRelativePC(address, match.getSize(), match.getBitmask(),
				target.getDestination(), addend, isTransparent);
		}
	}

	private static class PowerPC_HI16_LO16_InstructionRelocationEmitter
			implements FunctionInstructionSink {
		private final RelocationTableSynthesizerAnalyzer analyzer;
		private final Program program;
		private final RelocationTable relocationTable;
		private final Function function;

		public PowerPC_HI16_LO16_InstructionRelocationEmitter(
				RelocationTableSynthesizerAnalyzer analyzer, Function function) {
			this.analyzer = analyzer;
			this.program = analyzer.getProgram();
			this.relocationTable = analyzer.getRelocationTable();
			this.function = function;
		}

		@Override
		public boolean process(Instruction instruction) throws MemoryAccessException {
			if (!isLowCandidate(instruction)) {
				return false;
			}

			Register baseRegister = getLowBaseRegister(instruction);
			if (baseRegister == null) {
				return false;
			}

			ReferenceManager referenceManager = program.getReferenceManager();
			boolean foundRelocation = false;

			for (Reference reference : referenceManager
					.getReferencesFrom(instruction.getAddress())) {
				if (!isReferenceInteresting(reference, analyzer) || reference.getReferenceType()
						.isFlow()) {
					continue;
				}

				RelocationTarget target = RelocationTarget.get(program, reference);
				if (target == null) {
					continue;
				}

				RelocationTarget finalTarget = analyzer.getFinalRelocationTarget(target);
				Instruction hiInstruction = findDefiningLis(instruction, baseRegister);
				if (hiInstruction == null) {
					continue;
				}

				RelocationHighPair hiRelocation =
					addOrGetHi16Relocation(hiInstruction.getAddress(),
						finalTarget.getDestination());
				if (hiRelocation == null) {
					continue;
				}

				relocationTable.addLowPair(instruction.getAddress(), 4, LO16_BITMASK, hiRelocation,
					finalTarget.getOffset());
				foundRelocation = true;
			}

			return foundRelocation;
		}

		private RelocationHighPair addOrGetHi16Relocation(Address address, Address target) {
			Relocation relocation = relocationTable.getRelocationAt(address);
			if (relocation == null) {
				return relocationTable.addHighPair(address, 4, HI16_BITMASK, target);
			}
			if (!(relocation instanceof RelocationHighPair)) {
				return null;
			}

			RelocationHighPair highPair = (RelocationHighPair) relocation;
			if (!target.equals(highPair.getTarget())) {
				return null;
			}
			return highPair;
		}

		private Instruction findDefiningLis(Instruction instruction, Register register) {
			Listing listing = program.getListing();
			Instruction cursor = listing.getInstructionBefore(instruction.getAddress());

			while (cursor != null && function.getBody().contains(cursor.getAddress())) {
				if (isInstructionDefiningRegister(cursor, register)) {
					if (isLisInstruction(cursor)) {
						return cursor;
					}
					return null;
				}

				cursor = listing.getInstructionBefore(cursor.getAddress());
			}

			return null;
		}

		private boolean isInstructionDefiningRegister(Instruction instruction, Register register) {
			Register baseRegister = register.getBaseRegister();
			for (Object object : instruction.getResultObjects()) {
				if (object instanceof Register instructionRegister &&
					instructionRegister.getBaseRegister().equals(baseRegister)) {
					return true;
				}
			}
			return false;
		}

		private boolean isLowCandidate(Instruction instruction) {
			String mnemonic = normalizedMnemonic(instruction);
			return "lwz".equals(mnemonic) || "addi".equals(mnemonic);
		}

		private boolean isLisInstruction(Instruction instruction) {
			return "lis".equals(normalizedMnemonic(instruction));
		}

		private Register getLowBaseRegister(Instruction instruction) {
			String mnemonic = normalizedMnemonic(instruction);

			if ("lwz".equals(mnemonic)) {
				Object[] objects = instruction.getOpObjects(1);
				if (objects.length >= 2 && objects[1] instanceof Register register) {
					return register.getBaseRegister();
				}
			}
			else if ("addi".equals(mnemonic)) {
				Object[] objects = instruction.getOpObjects(1);
				if (objects.length >= 1 && objects[0] instanceof Register register) {
					return register.getBaseRegister();
				}
			}

			return null;
		}

		private String normalizedMnemonic(Instruction instruction) {
			String mnemonic = instruction.getMnemonicString();
			if (mnemonic.startsWith("_")) {
				return mnemonic.substring(1);
			}
			return mnemonic;
		}
	}

	@Override
	public List<FunctionInstructionSink> getFunctionInstructionSinks(
			RelocationTableSynthesizerAnalyzer analyzer, Function function,
			EvaluationReporter evaluationReporter, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		FunctionInstructionSink rel24Emitter = new PowerPC_REL24_InstructionRelocationEmitter(
			analyzer, function, evaluationReporter, monitor, log);
		FunctionInstructionSink rel14Emitter = new PowerPC_REL14_InstructionRelocationEmitter(
			analyzer, function, evaluationReporter, monitor, log);
		FunctionInstructionSink hiloEmitter =
			new PowerPC_HI16_LO16_InstructionRelocationEmitter(analyzer, function);

		return List.of(rel24Emitter, rel14Emitter, hiloEmitter);
	}

	@Override
	public boolean canAnalyze(Program program) {
		Processor processor = program.getLanguage().getProcessor();
		return processor.equals(Processor.findOrPossiblyCreateProcessor("PowerPC"));
	}
}
