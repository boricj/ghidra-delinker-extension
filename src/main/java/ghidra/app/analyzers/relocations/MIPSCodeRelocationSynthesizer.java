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
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Mask;
import ghidra.program.model.lang.OperandType;
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
import ghidra.util.DataConverter;

public class MIPSCodeRelocationSynthesizer
		extends FunctionInstructionSinkCodeRelocationSynthesizer {
	private static class MIPS_26_InstructionRelocationEmitter extends InstructionRelocationEmitter {
		private static final byte[] OPMASK_JTYPE = new byte[] { -1, -1, -1, 3 };

		public MIPS_26_InstructionRelocationEmitter(Program program,
				RelocationTable relocationTable, Function function) {
			super(program, relocationTable, function);
		}

		@Override
		public OperandValueRaw getOperandValueRaw(Instruction instruction, int opIdx)
				throws MemoryAccessException {
			int opType = instruction.getOperandType(opIdx);
			InstructionPrototype prototype = instruction.getPrototype();
			Mask valueMask = prototype.getOperandValueMask(opIdx);
			byte[] maskBytes = valueMask.getBytes();

			if (OperandType.isAddress(opType)) {
				if (Arrays.equals(maskBytes, OPMASK_JTYPE)) {
					return new OperandValueRaw(instruction, 0, 4);
				}
			}

			return null;
		}

		@Override
		public long computeTargetAddress(Instruction instruction, Reference reference,
				OperandValueRaw opValue) throws MemoryAccessException {
			long target = instruction.getAddress().getOffset() & 0xf0000000;
			return target | (opValue.unsignedValue & 0x3ffffff) << 2;
		}

		@Override
		public boolean emitRelocation(Instruction instruction, Reference reference,
				OperandValueRaw opValue, SymbolWithOffset symbol) throws MemoryAccessException {
			if (symbol.offset % 4 != 0) {
				return false;
			}

			relocationTable.addMIPS26(instruction.getAddress(), symbol.name, symbol.offset >> 2);
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
		private static final byte[] OPMASK_LOAD_STORE = new byte[] { -1, -1, -32, 3 };

		public MIPS_GPREL16_InstructionRelocationEmitter(Program program,
				RelocationTable relocationTable, Function function, Symbol fromSymbol) {
			super(program, relocationTable, function, fromSymbol);
		}

		@Override
		public OperandValueRaw getOperandValueRaw(Instruction instruction, int opIdx)
				throws MemoryAccessException {
			OperandValueRaw opValue = super.getOperandValueRaw(instruction, opIdx);
			if (opValue != null) {
				return opValue;
			}

			int opType = instruction.getOperandType(opIdx);
			InstructionPrototype prototype = instruction.getPrototype();
			Mask valueMask = prototype.getOperandValueMask(opIdx);
			byte[] maskBytes = valueMask.getBytes();

			if (OperandType.isAddress(opType)) {
				if (Arrays.equals(maskBytes, OPMASK_LOAD_STORE)) {
					return new OperandValueRaw(instruction, 0, 2);
				}
			}

			return opValue;
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
