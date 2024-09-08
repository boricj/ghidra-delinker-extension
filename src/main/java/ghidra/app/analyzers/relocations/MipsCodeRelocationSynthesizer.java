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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import ghidra.app.analyzers.relocations.emitters.BundleRelocationEmitter;
import ghidra.app.analyzers.relocations.emitters.FunctionInstructionSink;
import ghidra.app.analyzers.relocations.emitters.InstructionRelocationEmitter;
import ghidra.app.analyzers.relocations.emitters.RelativeNextInstructionRelocationEmitter;
import ghidra.app.analyzers.relocations.patterns.FixedOperandMatcher;
import ghidra.app.analyzers.relocations.patterns.OperandMatch;
import ghidra.app.analyzers.relocations.patterns.OperandMatcher;
import ghidra.app.analyzers.relocations.synthesizers.FunctionInstructionSinkCodeRelocationSynthesizer;
import ghidra.app.analyzers.relocations.utils.SymbolWithOffset;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.relocobj.RelocationHighPair;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.ProgramUtilities;
import ghidra.util.DataConverter;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class MipsCodeRelocationSynthesizer
		extends FunctionInstructionSinkCodeRelocationSynthesizer {
	private static class MIPS_26_InstructionRelocationEmitter extends InstructionRelocationEmitter {
		private static final OperandMatcher MATCHER_BIG_ENDIAN =
			new JtypeOperandMatcher(new Byte[] { 3, -1, -1, -1 }, 0x3ffffff);
		private static final OperandMatcher MATCHER_LITTLE_ENDIAN =
			new JtypeOperandMatcher(new Byte[] { -1, -1, -1, 3 }, 0x3ffffff);

		private static class JtypeOperandMatcher extends FixedOperandMatcher {
			private final long bitmask;

			public JtypeOperandMatcher(Byte[] operandMask, long bitmask) {
				super(operandMask);

				this.bitmask = bitmask;
			}

			@Override
			public OperandMatch createMatch(Instruction instruction, int operandIndex)
					throws MemoryAccessException {
				DataConverter dc = ProgramUtilities.getDataConverter(instruction.getProgram());
				long value = (dc.getInt(instruction.getBytes()) & bitmask) << 2;

				return new OperandMatch(operandIndex, 0, 4, bitmask, value);
			}
		}

		private final Set<Instruction> branchesToShiftByOne;

		public MIPS_26_InstructionRelocationEmitter(Program program,
				RelocationTable relocationTable, Function function,
				Set<Instruction> branchesToShiftByOne, TaskMonitor monitor, MessageLog log) {
			super(program, relocationTable, function, monitor, log);

			this.branchesToShiftByOne = branchesToShiftByOne;
		}

		@Override
		public boolean evaluate(Instruction instruction, OperandMatch match,
				SymbolWithOffset symbol, Reference reference) throws MemoryAccessException {
			Address fromAddress = instruction.getAddress();
			long origin = fromAddress.getUnsignedOffset() & 0xfffffffff0000000L;
			long target = reference.getToAddress().getUnsignedOffset();
			long addend = computeAddend(instruction, match, symbol, reference);

			if (addend < -0x4000000 || addend > 0x3ffffff || ((addend & 3) != 0)) {
				return false;
			}

			return (origin | match.getValue()) == target;
		}

		@Override
		protected void emit(Instruction instruction, OperandMatch match, SymbolWithOffset symbol,
				Reference reference) {
			RelocationTable relocationTable = getRelocationTable();
			Address address = instruction.getAddress();
			long addend = computeAddend(instruction, match, symbol, reference);

			if (branchesToShiftByOne.contains(instruction)) {
				addend -= 4;
				logBranchDelaySlotWithHI16(address, getMessageLog());
			}

			relocationTable.addMIPS26(address, symbol.name, addend);
		}

		private long computeAddend(Instruction instruction, OperandMatch match,
				SymbolWithOffset symbol, Reference reference) {
			long origin = instruction.getAddress().getUnsignedOffset() & 0xfffffffff0000000L;
			long addend = (origin | match.getValue()) - symbol.address;

			return addend;
		}

		@Override
		public Collection<OperandMatcher> getOperandMatchers() {
			if (getProgram().getMemory().isBigEndian()) {
				return List.of(MATCHER_BIG_ENDIAN);
			}
			else {
				return List.of(MATCHER_LITTLE_ENDIAN);
			}
		}
	}

	private static class MIPS_HI16LO16_BundleRelocationEmitter extends BundleRelocationEmitter {
		private final static String LUI = "lui";
		private final static String ADDIU = "addiu";
		private final static String ADDU = "addu";
		private final static String LWL = "lwl";
		private final static String SWL = "swl";
		private final static List<String> LOADS =
			List.of("lb", "lbu", "lh", "lhu", "lw", LWL, "lwr");
		private final static List<String> STORES = List.of("sb", "sh", "sw", SWL, "swr");

		private final DataConverter dc;

		public MIPS_HI16LO16_BundleRelocationEmitter(Program program,
				RelocationTable relocationTable, Function function, TaskMonitor monitor,
				MessageLog log) {
			super(program, relocationTable, function, monitor, log);

			this.dc = DataConverter.getInstance(program.getLanguage().isBigEndian());
		}

		@Override
		public boolean evaluateRoot(Reference reference, SymbolWithOffset symbol, Node node)
				throws MemoryAccessException {
			boolean foundRelocation = false;

			Instruction instruction = node.getInstruction();
			if (isLo16Candidate(instruction) &&
				!isReferenceOnOutputRegister(instruction, reference)) {
				foundRelocation |= evaluateLo16(reference, symbol, node, node, null, 0);
			}
			else {
				for (Node child : node.getChildren()) {
					foundRelocation |= evaluateRoot(reference, symbol, child);
				}
			}

			return foundRelocation;
		}

		@Override
		public boolean isInstructionReferenceRelatedToNode(Instruction instruction,
				Reference reference, Node node) {
			boolean result =
				super.isInstructionReferenceRelatedToNode(instruction, reference, node);
			Instruction parentInstruction = node.getInstruction();

			// Verify that inputs and output registers are coherent.
			Register outputRegister = getOutputRegister(parentInstruction);
			List<Register> inputRegisters;

			if (isReferenceOnOutputRegister(instruction, reference)) {
				inputRegisters = List.of(getOutputRegister(instruction));
			}
			else {
				inputRegisters = getInputRegisters(instruction);
			}

			if (outputRegister != null && inputRegisters != null) {
				result &= inputRegisters.contains(outputRegister);
			}

			return result;
		}

		public boolean evaluateLo16(Reference reference, SymbolWithOffset symbol, Node node,
				Node nodeLo16, Node extraNodeLo16, int extraAddend) throws MemoryAccessException {
			boolean foundRelocation = false;

			int extraNodeLo16Addend = 0;
			if (extraNodeLo16 != null) {
				extraNodeLo16Addend = (short) dc.getInt(extraNodeLo16.getInstruction().getBytes());
			}

			Instruction lo16Instruction = node.getInstruction();
			if (isLWL(lo16Instruction) || isSWL(lo16Instruction)) {
				extraAddend -= ((short) dc.getInt(lo16Instruction.getBytes())) % 4;
			}

			for (Node child : node.getChildren()) {
				Instruction instruction = child.getInstruction();

				if (isHi16Candidate(instruction)) {
					foundRelocation |= evaluateHi16(reference, symbol, child, nodeLo16,
						extraAddend + extraNodeLo16Addend);
				}
				else if (isLo16Candidate(instruction)) {
					foundRelocation |= evaluateLo16(reference, symbol, child, child, nodeLo16,
						extraAddend + extraNodeLo16Addend);
				}
				else {
					foundRelocation |= evaluateLo16(reference, symbol, child, nodeLo16,
						extraNodeLo16, extraAddend);
				}
			}

			return foundRelocation;
		}

		public boolean evaluateHi16(Reference reference, SymbolWithOffset symbol, Node node,
				Node nodeLo16, int extraAddend) throws MemoryAccessException {
			Instruction hi16 = node.getInstruction();
			Instruction lo16 = nodeLo16.getInstruction();

			long toAddress = reference.getToAddress().getOffset();
			long targetAddress = computeTargetAddress(hi16, lo16) + extraAddend;
			if (toAddress == targetAddress) {
				return emitRelocation(hi16, lo16, symbol, extraAddend);
			}

			return false;
		}

		private long computeTargetAddress(Instruction hi16, Instruction lo16)
				throws MemoryAccessException {
			long target = (dc.getInt(hi16.getBytes()) << 16) & 0xffffffffL;
			return target + (short) dc.getInt(lo16.getBytes());
		}

		private boolean emitRelocation(Instruction hi16, Instruction lo16, SymbolWithOffset symbol,
				int extraAddend)
				throws MemoryAccessException {
			// FIXME: handle HI16/LO16 addends greater than 15 bits.
			long lo16addend = symbol.offset - extraAddend;
			if (lo16addend > 0x7fff) {
				return false;
			}

			RelocationTable relocationTable = getRelocationTable();
			RelocationHighPair hiRel =
				relocationTable.addHighPair(hi16.getAddress(), 4, 0xFFFF, symbol.name);
			relocationTable.addLowPair(lo16.getAddress(), 4, 0xFFFF, hiRel, lo16addend);
			return true;
		}

		private CharSequence getNormalizedMnemonic(Instruction instruction) {
			String mnemonic = instruction.getMnemonicString();
			if (mnemonic.startsWith("_")) {
				return mnemonic.subSequence(1, mnemonic.length());
			}
			return mnemonic;
		}

		private boolean isLOAD(Instruction instruction) {
			return LOADS.contains(getNormalizedMnemonic(instruction));
		}

		private boolean isSTORE(Instruction instruction) {
			return STORES.contains(getNormalizedMnemonic(instruction));
		}

		private boolean isLOADSTORE(Instruction instruction) {
			return isLOAD(instruction) || isSTORE(instruction);
		}

		private boolean isLUI(Instruction instruction) {
			return LUI.equals(getNormalizedMnemonic(instruction));
		}

		private boolean isADDIU(Instruction instruction) {
			return ADDIU.equals(getNormalizedMnemonic(instruction));
		}

		private boolean isADDU(Instruction instruction) {
			return ADDU.equals(getNormalizedMnemonic(instruction));
		}

		private boolean isLWL(Instruction instruction) {
			return LWL.equals(getNormalizedMnemonic(instruction));
		}

		private boolean isSWL(Instruction instruction) {
			return SWL.equals(getNormalizedMnemonic(instruction));
		}

		private boolean isHi16Candidate(Instruction instruction) {
			return isLUI(instruction);
		}

		private boolean isLo16Candidate(Instruction instruction) {
			return isLOADSTORE(instruction) || isADDIU(instruction);
		}

		private boolean isReferenceOnOutputRegister(Instruction instruction, Reference reference) {
			return isLOADSTORE(instruction) && reference.getOperandIndex() == 0;
		}

		private List<Register> getInputRegisters(Instruction instruction) {
			if (isLOADSTORE(instruction)) {
				return List.of((Register) instruction.getOpObjects(1)[1]);
			}
			else if (isADDIU(instruction)) {
				return List.of((Register) instruction.getOpObjects(1)[0]);
			}
			else if (isADDU(instruction)) {
				return List.of((Register) instruction.getOpObjects(1)[0],
					(Register) instruction.getOpObjects(2)[0]);
			}

			return null;
		}

		private Register getOutputRegister(Instruction instruction) {
			if (isLOADSTORE(instruction) || isADDIU(instruction) || isADDU(instruction) ||
				isLUI(instruction)) {
				return (Register) instruction.getOpObjects(0)[0];
			}

			return null;
		}
	}

	/**
	 * The SYSTEM V APPLICATION BINARY INTERFACE MIPS® RISC Processor Supplement 3rd Edition
	 * defines R_MIPS_PC16 to be sign–extend(A) + S – P. This is borderline useless on MIPS
	 * since the branch instructions family uses immediates that are shifted right by two bits.
	 * The issue was identified back in 1999 [1] and GNU binutils unilaterally decided to fix
	 * it for good in 2005 [2]. It's been in the binutils history for almost two decades [3],
	 * obsoleting R_MIPS_GNU_REL16_S2.
	 * 
	 * The object file exporters will probably not emit these relocations under nominal
	 * conditions, but synthesizing these relocations will take care of primary references
	 * located inside branch instructions.
	 * 
	 * [1] https://sourceware.org/pipermail/binutils/1999-October/000952.html
	 * [2] https://sourceware.org/pipermail/binutils/2005-November/045157.html
	 * [3] https://github.com/bminor/binutils-gdb/commit/bad36eacdad37042c4efb1c5fbf48476b47de82b
	 */
	private static class MIPS_PC16_InstructionRelocationEmitter
			extends RelativeNextInstructionRelocationEmitter {
		private static final OperandMatcher MATCHER_BIG_ENDIAN =
			new ItypeOperandMatcher(new Byte[] { 0, 0, -1, -1 }, 0x0000ffffL);
		private static final OperandMatcher MATCHER_LITTLE_ENDIAN =
			new ItypeOperandMatcher(new Byte[] { -1, -1, 0, 0 }, 0x0000ffffL);

		private static class ItypeOperandMatcher extends FixedOperandMatcher {
			private final long bitmask;

			public ItypeOperandMatcher(Byte[] operandMask, long bitmask) {
				super(operandMask);

				this.bitmask = bitmask;
			}

			@Override
			public OperandMatch createMatch(Instruction instruction, int operandIndex)
					throws MemoryAccessException {
				DataConverter dc = ProgramUtilities.getDataConverter(instruction.getProgram());
				long value = ((long) (short) (dc.getInt(instruction.getBytes()) & bitmask)) << 2;

				return new OperandMatch(operandIndex, 0, 4, bitmask, value);
			}
		}

		private final Set<Instruction> branchesToShiftByOne;

		public MIPS_PC16_InstructionRelocationEmitter(Program program,
				RelocationTable relocationTable, Function function,
				Set<Instruction> branchesToShiftByOne, TaskMonitor monitor, MessageLog log) {
			super(program, relocationTable, function, monitor, log);

			this.branchesToShiftByOne = branchesToShiftByOne;
		}

		@Override
		public boolean evaluate(Instruction instruction, OperandMatch match,
				SymbolWithOffset symbol, Reference reference) throws MemoryAccessException {
			return ((match.getValue() & 3) == 0) &&
				super.evaluate(instruction, match, symbol, reference);
		}

		@Override
		public void emit(Instruction instruction, OperandMatch match, SymbolWithOffset symbol,
				Reference reference) {
			RelocationTable relocationTable = getRelocationTable();
			Address address = instruction.getAddress().add(match.getOffset());
			long addend = address.getUnsignedOffset() - symbol.address + match.getValue();
			boolean isTransparent = true;

			if (branchesToShiftByOne.contains(instruction)) {
				logBranchDelaySlotWithHI16(instruction.getAddress(), getMessageLog());
				addend -= 4;
				isTransparent = false;
			}

			relocationTable.addRelativePC(address, match.getSize(), match.getBitmask(), symbol.name,
				addend, isTransparent);
		}

		@Override
		public Collection<OperandMatcher> getOperandMatchers() {
			if (getProgram().getMemory().isBigEndian()) {
				return List.of(MATCHER_BIG_ENDIAN);
			}
			else {
				return List.of(MATCHER_LITTLE_ENDIAN);
			}
		}
	}

	private static class MIPS_GPREL16_InstructionRelocationEmitter
			extends InstructionRelocationEmitter {
		private static final OperandMatcher MATCHER_BIG_ENDIAN =
			new LoadStoreOperandMatcher(new Byte[] { 3, -32, -1, -1 }, 0x0000ffffL);
		private static final OperandMatcher MATCHER_LITTLE_ENDIAN =
			new LoadStoreOperandMatcher(new Byte[] { -1, -1, -32, 3 }, 0x0000ffffL);

		private static class LoadStoreOperandMatcher extends FixedOperandMatcher {
			private final long bitmask;

			public LoadStoreOperandMatcher(Byte[] bytes, long bitmask) {
				super(bytes);

				this.bitmask = bitmask;
			}

			@Override
			public OperandMatch createMatch(Instruction instruction, int operandIndex)
					throws MemoryAccessException {
				int size = getMaskLength();
				DataConverter dc = ProgramUtilities.getDataConverter(instruction.getProgram());
				long value = (short) (dc.getInt(instruction.getBytes()) & bitmask);

				return new OperandMatch(operandIndex, 0, size, bitmask, value);
			}
		}

		private final Register gp;

		public MIPS_GPREL16_InstructionRelocationEmitter(Program program,
				RelocationTable relocationTable, Function function,
				TaskMonitor monitor, MessageLog log) {
			super(program, relocationTable, function, monitor, log);

			gp = program.getRegister("gp");
		}

		@Override
		public Collection<OperandMatcher> getOperandMatchers() {
			if (getProgram().getMemory().isBigEndian()) {
				return List.of(MATCHER_BIG_ENDIAN);
			}
			else {
				return List.of(MATCHER_LITTLE_ENDIAN);
			}
		}

		@Override
		public boolean evaluate(Instruction instruction, OperandMatch match,
				SymbolWithOffset symbol, Reference reference)
				throws MemoryAccessException {
			ProgramContext programContext = getProgram().getProgramContext();
			BigInteger gpValue = programContext.getValue(gp, instruction.getAddress(), false);
			if (gpValue == null) {
				return false;
			}

			Object[] objects = instruction.getOpObjects(match.getOperandIndex());
			if (!Arrays.asList(objects).contains(gp)) {
				return false;
			}

			long origin = gpValue.longValue();
			long relative = match.getValue();
			long target = reference.getToAddress().getUnsignedOffset();

			return target == origin + relative;
		}

		@Override
		public void emit(Instruction instruction, OperandMatch match, SymbolWithOffset symbol,
				Reference reference) {
			RelocationTable relocationTable = getRelocationTable();
			Address address = instruction.getAddress().add(match.getOffset());
			long addend = reference.getToAddress().getUnsignedOffset() - symbol.address;

			relocationTable.addRelativeSymbol(address, match.getSize(), match.getBitmask(),
				symbol.name,
				addend, "$gp");
		}
	}

	private static class MIPS_GOT16_InstructionRelocationEmitter
			extends InstructionRelocationEmitter {
		private static final OperandMatcher MATCHER_BIG_ENDIAN =
			new LoadStoreOperandMatcher(new Byte[] { 3, -32, -1, -1 }, 0x0000ffffL);
		private static final OperandMatcher MATCHER_LITTLE_ENDIAN =
			new LoadStoreOperandMatcher(new Byte[] { -1, -1, -32, 3 }, 0x0000ffffL);

		private static class LoadStoreOperandMatcher extends FixedOperandMatcher {
			private final long bitmask;

			public LoadStoreOperandMatcher(Byte[] bytes, long bitmask) {
				super(bytes);

				this.bitmask = bitmask;
			}

			@Override
			public OperandMatch createMatch(Instruction instruction, int operandIndex)
					throws MemoryAccessException {
				int size = getMaskLength();
				DataConverter dc = ProgramUtilities.getDataConverter(instruction.getProgram());
				long value = (short) (dc.getInt(instruction.getBytes()) & bitmask);

				return new OperandMatch(operandIndex, 0, size, bitmask, value);
			}
		}

		private final Register gp;
		private final Register t9;
		private final Long got;

		public MIPS_GOT16_InstructionRelocationEmitter(Program program,
				RelocationTable relocationTable, Function function,
				TaskMonitor monitor, MessageLog log) {
			super(program, relocationTable, function, monitor, log);

			gp = program.getRegister("gp");
			t9 = program.getRegister("t9");

			Listing listing = getProgram().getListing();
			List<Instruction> prologue = StreamSupport
					.stream(listing.getInstructions(getFunction().getBody(), true).spliterator(),
						false)
					.limit(3)
					.collect(Collectors.toList());

			if (prologue.size() < 3) {
				got = null;
				return;
			}

			Instruction i0 = prologue.get(0);
			Instruction i1 = prologue.get(1);
			Instruction i2 = prologue.get(2);

			if (!i0.getMnemonicString().equals("lui") ||
				!i1.getMnemonicString().equals("addiu") ||
				!i2.getMnemonicString().equals("addu")) {
				got = null;
				return;
			}

			if (!i0.getOpObjects(0)[0].equals(gp) ||
				!i1.getOpObjects(0)[0].equals(gp) || !i1.getOpObjects(1)[0].equals(gp) ||
				!i2.getOpObjects(0)[0].equals(gp) || !i2.getOpObjects(1)[0].equals(gp) ||
				!i2.getOpObjects(2)[0].equals(t9)) {
				got = null;
				return;
			}

			long lui = ((Scalar) i0.getOpObjects(1)[0]).getUnsignedValue();
			long addiu = ((Scalar) i1.getOpObjects(2)[0]).getSignedValue();
			long addu = function.getEntryPoint().getUnsignedOffset();
			got = (lui << 16) + addiu + addu;
		}

		@Override
		public Collection<OperandMatcher> getOperandMatchers() {
			if (getProgram().getMemory().isBigEndian()) {
				return List.of(MATCHER_BIG_ENDIAN);
			}
			else {
				return List.of(MATCHER_LITTLE_ENDIAN);
			}
		}

		@Override
		public boolean evaluate(Instruction instruction, OperandMatch match,
				SymbolWithOffset symbol, Reference reference)
				throws MemoryAccessException {
			if (got == null) {
				return false;
			}

			Object[] objects = instruction.getOpObjects(match.getOperandIndex());
			if (!Arrays.asList(objects).contains(gp)) {
				return false;
			}

			ProgramContext programContext = getProgram().getProgramContext();
			BigInteger gpValue = programContext.getValue(gp, instruction.getAddress(), false);
			if (gpValue != null) {
				return false;
			}

			long origin = got;
			long relative = match.getValue();
			long target = reference.getToAddress().getUnsignedOffset();

			return target == origin + relative;
		}

		@Override
		public void emit(Instruction instruction, OperandMatch match, SymbolWithOffset symbol,
				Reference reference) {
			RelocationTable relocationTable = getRelocationTable();
			Address address = instruction.getAddress().add(match.getOffset());
			long addend = reference.getToAddress().getUnsignedOffset() - symbol.address;

			relocationTable.addRelativeSymbol(address, match.getSize(), match.getBitmask(),
				symbol.name,
				addend, "$got");
		}
	}

	@Override
	public List<FunctionInstructionSink> getFunctionInstructionSinks(Program program,
			RelocationTable relocationTable, Function function, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		Set<Instruction> branchesToShiftByOne =
			detectBranchDelaySlotsWithHI16(program, function, monitor);

		List<FunctionInstructionSink> sinks = new ArrayList<>();
		sinks.add(new MIPS_26_InstructionRelocationEmitter(program, relocationTable, function,
			branchesToShiftByOne, monitor, log));
		sinks.add(new MIPS_HI16LO16_BundleRelocationEmitter(program, relocationTable, function,
			monitor, log));
		sinks.add(new MIPS_PC16_InstructionRelocationEmitter(program, relocationTable, function,
			branchesToShiftByOne, monitor, log));
		sinks.add(new MIPS_GPREL16_InstructionRelocationEmitter(program, relocationTable,
			function, monitor, log));
		sinks.add(new MIPS_GOT16_InstructionRelocationEmitter(program, relocationTable, function,
			monitor, log));

		return sinks;
	}

	/**
	 * The MIPS instruction set has the following quirks that can combine into a complete mess:
	 * 	* It relies on pairs of HI16/LO16 relocations to load absolute 32-bit pointers.
	 * 	* It has branch delay slots.
	 *
	 * One common MIPS optimization trick done by assemblers is to fill these delay slots by
	 * duplicating the target instruction inside the delay slot and shifting the branch target one
	 * instruction forward, resulting in an instruction stream shortened by one instruction.
	 *
	 * Unfortunately, some assemblers can decide to vacuum up instructions with a HI16 relocation,
	 * meaning that a LO16 relocation could have multiple HI16 relocation parents. This pattern
	 * can't be expressed by any object file format that I'm aware of. Therefore, we need to undo
	 * this optimization by shifting these branch targets back one instruction in order to recover
	 * valid HI16/LO16 relocation pairs.
	 */
	private Set<Instruction> detectBranchDelaySlotsWithHI16(Program program, Function function,
			TaskMonitor monitor) throws CancelledException {
		Set<Instruction> set = new HashSet<>();
		CodeBlockModel codeBlockModel = new BasicBlockModel(program);

		CodeBlockIterator it = codeBlockModel.getCodeBlocksContaining(function.getBody(), monitor);
		while (it.hasNext()) {
			set.addAll(
				detectBranchDelaySlotsWithHI16_CodeBlock(program, function, it.next(), monitor));
		}

		return set;
	}

	private Set<Instruction> detectBranchDelaySlotsWithHI16_CodeBlock(Program program,
			Function function, CodeBlock codeBlock, TaskMonitor monitor) throws CancelledException {
		CodeBlockReferenceIterator refIt = codeBlock.getSources(monitor);
		List<CodeBlock> sources = new ArrayList<>();
		CodeBlock fallThrough = null;

		while (refIt.hasNext()) {
			CodeBlockReference ref = refIt.next();
			CodeBlock sourceCodeBlock = ref.getSourceBlock();
			if (!function.getBody().contains(sourceCodeBlock)) {
				// This deoptimization is strictly scoped to within a function, bail out.
				return Collections.emptySet();
			}

			if (ref.getFlowType() == FlowType.FALL_THROUGH) {
				fallThrough = sourceCodeBlock;
			}
			else {
				sources.add(sourceCodeBlock);
			}
		}

		if (!sources.isEmpty() && fallThrough != null) {
			return detectBranchDelaySlotsWithHI16_CodeBlockSources(program, function, codeBlock,
				sources);
		}

		return Collections.emptySet();
	}

	private Set<Instruction> detectBranchDelaySlotsWithHI16_CodeBlockSources(Program program,
			Function function, CodeBlock codeBlock, List<CodeBlock> sources)
			throws CancelledException {
		Listing listing = program.getListing();
		Instruction targetInstruction =
			(Instruction) listing.getCodeUnitAt(codeBlock.getMinAddress());
		Instruction previousInstruction =
			(Instruction) listing.getCodeUnitBefore(targetInstruction.getAddress());
		if (!previousInstruction.getMnemonicString().equals("lui") &&
			!previousInstruction.getMnemonicString().equals("_lui")) {
			return Collections.emptySet();
		}

		return sources.stream()
				.map(c -> (Instruction) listing.getCodeUnitContaining(c.getMaxAddress()))
				.filter(i -> {
					try {
						return Arrays.equals(i.getBytes(), previousInstruction.getBytes());
					}
					catch (MemoryAccessException ex) {
						return false;
					}
				})
				.map(i -> (Instruction) listing.getCodeUnitBefore(i.getAddress()))
				.collect(Collectors.toSet());
	}

	private static void logBranchDelaySlotWithHI16(Address address, MessageLog log) {
		log.appendMsg(address.toString(),
			"Branch instruction target adjusted to deoptimize possible HI16 relocation inside delay slot");
	}

	@Override
	public boolean canAnalyze(Program program) {
		// Check language
		Processor processor = program.getLanguage().getProcessor();
		return processor.equals(Processor.findOrPossiblyCreateProcessor("MIPS")) ||
			processor.equals(Processor.findOrPossiblyCreateProcessor("PSX"));
	}
}
