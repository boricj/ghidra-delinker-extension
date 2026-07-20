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
import ghidra.program.model.relocobj.RelocationGang;
import ghidra.program.model.relocobj.RelocationGroup;
import ghidra.program.model.relocobj.RelocationGangRoleDescriptor;
import ghidra.program.model.relocobj.RelocationTable.RelocationLocation;
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
		if (containsRelocationRoleAt(instruction.getAddress(), RelocationGangRoleDescriptor.HIGH_PAIR)) {
			return true;
		}

		Address previous = instruction.getAddress().subtract(4);
		if (containsAddendAt(previous, RelocationGangRoleDescriptor.PC_RELATIVE, -2) ||
			containsAddendAt(previous, RelocationGangRoleDescriptor.REGION_RELATIVE, -1)) {
			return true;
		}

		return false;
	}

	private boolean containsRelocationRoleAt(Address address, RelocationGangRoleDescriptor role) {
		for (RelocationLocation location : relocationTable.getRelocationLocationsAt(address)) {
			RelocationGroup group = relocationTable.getRelocationGroup(location);

			RelocationGang gang = group.getGangs().get(location.gangIndex());
			if (RelocationGangRoleDescriptor.derive(group, location.gangIndex()) == role) {
				return true;
			}
		}

		return false;
	}

	private boolean containsAddendAt(Address address, RelocationGangRoleDescriptor role,
			long expectedAddend) {
		for (RelocationLocation location : relocationTable.getRelocationLocationsAt(address)) {
			RelocationGroup group = relocationTable.getRelocationGroup(location);

			RelocationGang gang = group.getGangs().get(location.gangIndex());
			if (RelocationGangRoleDescriptor.derive(group, location.gangIndex()) != role) {
				continue;
			}

			long addend =
				group.getAddend() + gang.getEntries().get(location.entryIndex()).localAddend();
			if (addend == expectedAddend) {
				return true;
			}
		}

		return false;
	}
}
