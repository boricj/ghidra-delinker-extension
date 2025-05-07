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

import static ghidra.app.util.ProgramUtil.getBitmask;

import java.util.Collection;
import java.util.List;

import ghidra.app.analyzers.RelocationTableSynthesizerAnalyzer;
import ghidra.app.analyzers.relocations.emitters.AbsoluteInstructionRelocationEmitter;
import ghidra.app.analyzers.relocations.emitters.FunctionInstructionSink;
import ghidra.app.analyzers.relocations.emitters.RelativeNextInstructionRelocationEmitter;
import ghidra.app.analyzers.relocations.patterns.OperandMatch;
import ghidra.app.analyzers.relocations.patterns.OperandMatcher;
import ghidra.app.analyzers.relocations.patterns.SlidingOperandMatcher;
import ghidra.app.analyzers.relocations.synthesizers.FunctionInstructionSinkCodeRelocationSynthesizer;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.ProgramUtilities;
import ghidra.util.DataConverter;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class X86CodeRelocationSynthesizer extends FunctionInstructionSinkCodeRelocationSynthesizer {
	private static class X86InstructionAbsoluteRelocationEmitter
			extends AbsoluteInstructionRelocationEmitter {
		private static class X86PrefixedOperandMatcher extends SlidingOperandMatcher {
			private final int prefixLength;

			public X86PrefixedOperandMatcher(Byte[] mask, int prefixLength) {
				super(mask);
				this.prefixLength = prefixLength;
			}

			@Override
			public OperandMatch createMatch(Instruction instruction, int operandIndex, int offset)
					throws MemoryAccessException {
				offset += prefixLength;
				int size = getMaskLength() - prefixLength;

				DataConverter dc = ProgramUtilities.getDataConverter(instruction.getProgram());
				long value = dc.getValue(instruction.getBytes(), offset, size);

				return new OperandMatch(operandIndex, offset, size, getBitmask(size),
					value);
			}
		}

		private static final OperandMatcher OPERANDMATCHER_MOD_RM_EA_4BYTES =
			new X86PrefixedOperandMatcher(new Byte[] { 0x07, -1, -1, -1, -1 }, 1);
		private static final OperandMatcher OPERANDMATCHER_MOD_RM_SIB_4BYTES =
			new X86PrefixedOperandMatcher(new Byte[] { -1, -1, -1, -1, -1 }, 1);
		private static final OperandMatcher OPERANDMATCHER_SIB_4BYTES =
			new X86PrefixedOperandMatcher(new Byte[] { -8, -1, -1, -1, -1 }, 1);

		private static final Collection<OperandMatcher> OPERAND_MATCHERS = List.of(
			OPERANDMATCHER_MOD_RM_EA_4BYTES,
			OPERANDMATCHER_MOD_RM_SIB_4BYTES,
			OPERANDMATCHER_SIB_4BYTES,
			SlidingOperandMatcher.UNSIGNED_4BYTES);

		public X86InstructionAbsoluteRelocationEmitter(RelocationTableSynthesizerAnalyzer analyzer,
				Function function, TaskMonitor monitor, MessageLog log) {
			super(analyzer, function, monitor, log);
		}

		@Override
		public Collection<OperandMatcher> getOperandMatchers() {
			return OPERAND_MATCHERS;
		}
	}

	private static class X86InstructionRelativeRelocationEmitter
			extends RelativeNextInstructionRelocationEmitter {

		private static final Collection<OperandMatcher> OPERAND_MATCHERS = List.of(
			SlidingOperandMatcher.SIGNED_1BYTE,
			SlidingOperandMatcher.SIGNED_2BYTES,
			SlidingOperandMatcher.SIGNED_4BYTES);

		public X86InstructionRelativeRelocationEmitter(RelocationTableSynthesizerAnalyzer analyzer,
				Function function, TaskMonitor monitor, MessageLog log) {
			super(analyzer, function, monitor, log);
		}

		@Override
		public Collection<OperandMatcher> getOperandMatchers() {
			return OPERAND_MATCHERS;
		}
	}

	@Override
	public List<FunctionInstructionSink> getFunctionInstructionSinks(
			RelocationTableSynthesizerAnalyzer analyzer, Function function, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		var absolute =
			new X86InstructionAbsoluteRelocationEmitter(analyzer, function, monitor, log);
		var relative =
			new X86InstructionRelativeRelocationEmitter(analyzer, function, monitor, log);

		return List.of(absolute, relative);
	}

	@Override
	public boolean canAnalyze(Program program) {
		// Check language
		Processor processor = program.getLanguage().getProcessor();
		return processor.equals(Processor.findOrPossiblyCreateProcessor("x86"));
	}
}
