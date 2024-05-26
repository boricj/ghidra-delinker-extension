//Detect LUI instructions without resynthesized HI16 relocations.
//@author Jean-Baptiste Boric
//@category Analysis.MIPS
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.relocobj.Relocation;
import ghidra.program.model.relocobj.RelocationHighPair;
import ghidra.program.model.relocobj.RelocationMIPS26;
import ghidra.program.model.relocobj.RelocationRelativePC;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.program.model.scalar.Scalar;

public class MipsDetectMissingHI16Relocations extends GhidraScript {
	private FunctionManager functionManager;
	private Listing listing;
	private RelocationTable relocationTable;

	private long luiMinValue;
	private long luiMaxValue;
	private AddressSet uncoveredInstructions;

	@Override
	public void run() throws Exception {
		functionManager = currentProgram.getFunctionManager();
		listing = currentProgram.getListing();
		relocationTable = RelocationTable.get(currentProgram);

		Address minAddress = askAddress("Target values", "Start address");
		Address maxAddress = askAddress("Target values", "End address");

		luiMinValue = (minAddress.getUnsignedOffset() >> 16) & 0xffff;
		luiMaxValue = ((maxAddress.getUnsignedOffset() + 0xffff) >> 16) & 0xffff;
		uncoveredInstructions = new AddressSet();

		for (Function function : functionManager.getFunctions(currentSelection, true)) {
			processFunction(function);
		}

		if (!uncoveredInstructions.isEmpty() && !isRunningHeadless()) {
			String msg = String.format("LUI instructions [%04x; %04x] not covered by a relocation",
				luiMinValue, luiMaxValue);
			show(msg, uncoveredInstructions);
		}
	}

	private void processFunction(Function function) throws Exception {
		for (Instruction instruction : listing.getInstructions(function.getBody(), true)) {
			if (isPossibleHI16(instruction) && !isCoveredHI16(instruction)) {
				String msg = String.format("%s> Possible LUI without HI16 relocation: %s\n",
					instruction.getAddress(), instruction);
				writer.write(msg);
				uncoveredInstructions.add(instruction.getMinAddress(), instruction.getMaxAddress());
			}
		}
	}

	private boolean isPossibleHI16(Instruction instruction) {
		if (instruction.getMnemonicString().contains("lui")) {
			Scalar scalar = (Scalar) instruction.getOpObjects(1)[0];
			long value = scalar.getUnsignedValue();

			return value >= luiMinValue && value < luiMaxValue;
		}

		return false;
	}

	private boolean isCoveredHI16(Instruction instruction) {
		Relocation rel = relocationTable.getRelocationAt(instruction.getAddress());
		if (rel == null) {
			rel = relocationTable.getRelocationAt(instruction.getAddress().subtract(4));

			if (rel instanceof RelocationRelativePC) {
				return ((RelocationRelativePC) rel).getAddend() == -2;
			}
			else if (rel instanceof RelocationMIPS26) {
				return ((RelocationMIPS26) rel).getAddend() == -1;
			}
		}

		return rel instanceof RelocationHighPair;
	}
}
