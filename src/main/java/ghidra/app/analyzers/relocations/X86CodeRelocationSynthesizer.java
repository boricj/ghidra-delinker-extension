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

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import ghidra.app.analyzers.relocations.emitters.AbsoluteInstructionRelocationEmitter;
import ghidra.app.analyzers.relocations.emitters.FunctionInstructionSink;
import ghidra.app.analyzers.relocations.emitters.FunctionInstructionSinkCodeRelocationSynthesizer;
import ghidra.app.analyzers.relocations.emitters.InstructionRelocationEmitter;
import ghidra.app.analyzers.relocations.emitters.RelativeNextInstructionRelocationEmitter;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class X86CodeRelocationSynthesizer extends FunctionInstructionSinkCodeRelocationSynthesizer {
	private static class X86InstructionAbsoluteRelocationEmitter
			extends AbsoluteInstructionRelocationEmitter {
		private static final List<Byte> OPMASK_MOD_RM_EA_4BYTES =
			Arrays.asList(new Byte[] { 0x07, -1, -1, -1, -1 });
		private static final List<Byte> OPMASK_SIB_4BYTES =
			Arrays.asList(new Byte[] { -8, -1, -1, -1, -1 });

		private static final List<List<Byte>> EXTRA_MASKS =
			List.of(OPMASK_MOD_RM_EA_4BYTES, OPMASK_SIB_4BYTES);
		private static final List<List<Byte>> MASKS =
			Stream.concat(MASKS_ALLONES.stream(), EXTRA_MASKS.stream()).toList();

		public X86InstructionAbsoluteRelocationEmitter(Program program,
				RelocationTable relocationTable, Function function, TaskMonitor monitor,
				MessageLog log) {
			super(program, relocationTable, function, monitor, log);
		}

		@Override
		public List<List<Byte>> getMasks() {
			return MASKS;
		}

		@Override
		public int getSizeFromMask(List<Byte> mask) {
			if (mask.equals(OPMASK_MOD_RM_EA_4BYTES)) {
				return 4;
			}
			else if (mask.equals(OPMASK_SIB_4BYTES)) {
				return 4;
			}

			return super.getSizeFromMask(mask);
		}

		@Override
		public int indexOfMask(List<Byte> instructionOperandMask, List<Byte> operandMask) {
			int offset = super.indexOfMask(instructionOperandMask, operandMask);
			if (offset != -1) {
				if (operandMask.equals(OPMASK_MOD_RM_EA_4BYTES)) {
					offset += 1;
				}
				else if (operandMask.equals(OPMASK_SIB_4BYTES)) {
					offset += 1;
				}
			}

			return offset;
		}
	}

	@Override
	public List<FunctionInstructionSink> getFunctionInstructionSinks(Program program,
			RelocationTable relocationTable, Function function, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		InstructionRelocationEmitter absolute =
			new X86InstructionAbsoluteRelocationEmitter(program, relocationTable, function, monitor,
				log);
		InstructionRelocationEmitter relative =
			new RelativeNextInstructionRelocationEmitter(program, relocationTable, function,
				monitor, log);

		return List.of(absolute, relative);
	}

	@Override
	public boolean canAnalyze(Program program) {
		// Check language
		Processor processor = program.getLanguage().getProcessor();
		return processor.equals(Processor.findOrPossiblyCreateProcessor("x86"));
	}
}
