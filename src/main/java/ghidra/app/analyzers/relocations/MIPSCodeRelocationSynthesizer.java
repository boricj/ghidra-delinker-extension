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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.analyzers.relocations.emitters.BundleRelocationEmitter;
import ghidra.app.analyzers.relocations.emitters.FunctionInstructionSink;
import ghidra.app.analyzers.relocations.emitters.FunctionInstructionSinkCodeRelocationSynthesizer;
import ghidra.app.analyzers.relocations.emitters.InstructionRelocationEmitter;
import ghidra.app.analyzers.relocations.emitters.SymbolRelativeInstructionRelocationEmitter;
import ghidra.app.analyzers.relocations.utils.SymbolWithOffset;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.relocobj.RelocationHighPair;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramUtilities;
import ghidra.util.DataConverter;

public class MIPSCodeRelocationSynthesizer
		extends FunctionInstructionSinkCodeRelocationSynthesizer {
	private static class MIPS_26_InstructionRelocationEmitter extends InstructionRelocationEmitter {
		private static final List<Byte> OPMASK_JTYPE = Arrays.asList(new Byte[] { -1, -1, -1, 3 });

		public MIPS_26_InstructionRelocationEmitter(Program program,
				RelocationTable relocationTable, Function function) {
			super(program, relocationTable, function);
		}

		@Override
		public List<List<Byte>> getMasks() {
			return List.of(OPMASK_JTYPE);
		}

		@Override
		public long computeValue(Instruction instruction, int operandIndex, Reference reference,
				int offset, List<Byte> mask) throws MemoryAccessException {
			DataConverter dc = ProgramUtilities.getDataConverter(instruction.getProgram());
			long value = dc.getValue(instruction.getBytes(), offset, getSizeFromMask(mask));
			return (value & 0x3ffffff) << 2;
		}

		@Override
		public boolean matches(Instruction instruction, int operandIndex, Reference reference,
				int offset, List<Byte> mask) throws MemoryAccessException {
			long origin = instruction.getAddress().getUnsignedOffset() & 0xfffffffff0000000L;
			long value = computeValue(instruction, operandIndex, reference, offset, mask);
			long target = reference.getToAddress().getUnsignedOffset();

			return (origin | value) == target;
		}

		@Override
		public long computeAddend(Instruction instruction, int operandIndex,
				SymbolWithOffset symbol, Reference reference, int offset, List<Byte> mask)
				throws MemoryAccessException {
			return symbol.offset >> 2;
		}

		@Override
		public boolean emitRelocation(Instruction instruction, int operandIndex,
				SymbolWithOffset symbol, Reference reference, int offset, List<Byte> mask,
				long addend) throws MemoryAccessException {
			if (addend < 0 || addend > 0x3ffffff) {
				return false;
			}

			RelocationTable relocationTable = getRelocationTable();
			Address fromAddress = instruction.getAddress();

			relocationTable.addMIPS26(fromAddress.add(offset), symbol.name, addend);
			return true;
		}
	}

	private static class MIPS_HI16LO16_BundleRelocationEmitter extends BundleRelocationEmitter {
		private final DataConverter dc;

		public MIPS_HI16LO16_BundleRelocationEmitter(Program program,
				RelocationTable relocationTable, Function function) {
			super(program, relocationTable, function);

			this.dc = DataConverter.getInstance(program.getLanguage().isBigEndian());
		}

		@Override
		public boolean evaluateRoot(Reference reference, SymbolWithOffset symbol, Node node)
				throws MemoryAccessException {
			boolean foundRelocation = false;

			Instruction instruction = node.getInstruction();
			if (isLo16Candidate(instruction)) {
				foundRelocation |= evaluateLo16(reference, symbol, node, node);
			}
			else {
				for (Node child : node.getChildren()) {
					foundRelocation |= evaluateRoot(reference, symbol, child);
				}
			}

			return foundRelocation;
		}

		public boolean evaluateLo16(Reference reference, SymbolWithOffset symbol, Node node,
				Node nodeLo16) throws MemoryAccessException {
			boolean foundRelocation = false;

			for (Node child : node.getChildren()) {
				Instruction instruction = child.getInstruction();

				if (isHi16Candidate(instruction)) {
					foundRelocation |= evaluateHi16(reference, symbol, child, nodeLo16);
				}
				else if (isLo16Candidate(instruction)) {
					foundRelocation |= evaluateLo16(reference, symbol, child, child);
					foundRelocation |= evaluateLo16(reference, symbol, child, nodeLo16);
				}
				else {
					foundRelocation |= evaluateLo16(reference, symbol, child, nodeLo16);
				}
			}

			return foundRelocation;
		}

		public boolean evaluateHi16(Reference reference, SymbolWithOffset symbol, Node node,
				Node nodeLo16) throws MemoryAccessException {
			Instruction hi16 = node.getInstruction();
			Instruction lo16 = nodeLo16.getInstruction();

			long toAddress = reference.getToAddress().getOffset();
			long targetAddress = computeTargetAddress(hi16, lo16);
			if (toAddress == targetAddress) {
				return emitRelocation(hi16, lo16, symbol);
			}

			return false;
		}

		private long computeTargetAddress(Instruction hi16, Instruction lo16)
				throws MemoryAccessException {
			long target = (dc.getInt(hi16.getBytes()) << 16) & 0xffffffffL;
			return target + (short) dc.getInt(lo16.getBytes());
		}

		private boolean emitRelocation(Instruction hi16, Instruction lo16, SymbolWithOffset symbol)
				throws MemoryAccessException {
			// FIXME: handle HI16/LO16 addends greater than 15 bits.
			if (symbol.offset > 0x7fff) {
				return false;
			}

			RelocationHighPair hiRel =
				relocationTable.addHighPair(hi16.getAddress(), 4, 0xFFFF, symbol.name);
			relocationTable.addLowPair(lo16.getAddress(), 4, 0xFFFF, hiRel, symbol.offset);
			return true;
		}

		private boolean isHi16Candidate(Instruction instruction) {
			List<String> mnemonics = List.of("lui");
			String mnemonic = instruction.getMnemonicString();
			if (mnemonic.startsWith("_")) {
				mnemonic = mnemonic.substring(1);
			}

			return mnemonics.contains(mnemonic);
		}

		private boolean isLo16Candidate(Instruction instruction) {
			List<String> mnemonics =
				List.of("addiu", "lb", "lbu", "lh", "lhu", "lw", "sb", "sh", "sw");
			String mnemonic = instruction.getMnemonicString();
			if (mnemonic.startsWith("_")) {
				mnemonic = mnemonic.substring(1);
			}

			return mnemonics.contains(mnemonic);
		}
	}

	private static class MIPS_GPREL16_InstructionRelocationEmitter
			extends SymbolRelativeInstructionRelocationEmitter {
		private static final List<Byte> OPMASK_LOAD_STORE =
			Arrays.asList(new Byte[] { -1, -1, -32, 3 });

		public MIPS_GPREL16_InstructionRelocationEmitter(Program program,
				RelocationTable relocationTable, Function function, Symbol fromSymbol) {
			super(program, relocationTable, function, fromSymbol);
		}

		@Override
		public List<List<Byte>> getMasks() {
			return List.of(OPMASK_LOAD_STORE);
		}

		@Override
		public int getSizeFromMask(List<Byte> mask) {
			return 2;
		}
	}

	@Override
	public List<FunctionInstructionSink> getFunctionInstructionSinks(Program program,
			RelocationTable relocationTable, Function function) {
		List<FunctionInstructionSink> sinks = new ArrayList<>();
		sinks.add(new MIPS_26_InstructionRelocationEmitter(program, relocationTable, function));
		sinks.add(new MIPS_HI16LO16_BundleRelocationEmitter(program, relocationTable, function));

		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator _gp = symbolTable.getSymbols("_gp");
		if (_gp.hasNext()) {
			sinks.add(new MIPS_GPREL16_InstructionRelocationEmitter(program, relocationTable,
				function, _gp.next()));
		}

		return sinks;
	}

	@Override
	public boolean canAnalyze(Program program) {
		// Check language
		Processor processor = program.getLanguage().getProcessor();
		return processor.equals(Processor.findOrPossiblyCreateProcessor("MIPS")) ||
			processor.equals(Processor.findOrPossiblyCreateProcessor("PSX"));
	}
}
