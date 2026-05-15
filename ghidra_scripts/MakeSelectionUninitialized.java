//Split selected range into its own memory block and convert to uninitialized data.
//@author Jean-Baptiste Boric
//@category Project
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockException;

public class MakeSelectionUninitialized extends GhidraScript {

	private record DataSnapshot(Address address, DataType dataType, int length) {
	}

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			printerr("No program is open.");
			return;
		}

		AddressSetView selection = currentSelection;
		if (selection == null || selection.isEmpty()) {
			printerr("Select exactly one contiguous address range.");
			return;
		}

		if (selection.getNumAddressRanges() != 1) {
			printerr("Selection must be a single contiguous range.");
			return;
		}

		AddressRange selectedRange = selection.getFirstRange();
		Address start = selectedRange.getMinAddress();
		Address end = selectedRange.getMaxAddress();

		Memory memory = currentProgram.getMemory();
		MemoryBlock originalBlock = memory.getBlock(start);
		if (originalBlock == null) {
			printerr("Selection start is not inside a memory block.");
			return;
		}

		if (!originalBlock.contains(end)) {
			printerr("Selection spans multiple memory blocks; select within one block.");
			return;
		}

		if (!validateSupportedBlock(originalBlock)) {
			return;
		}

		Listing listing = currentProgram.getListing();
		List<DataSnapshot> snapshots = snapshotDefinedData(listing, selection);

		int tx = currentProgram.startTransaction("Make selection uninitialized and restore data");
		boolean commit = false;
		boolean convertedToUninitialized = false;
		try {
			MemoryBlock selectedBlock = isolateSelectedBlock(memory, originalBlock, start, end);

			if (selectedBlock.isInitialized()) {
				memory.convertToUninitialized(selectedBlock);
				convertedToUninitialized = true;
			}

			restoreDefinedData(listing, start, end, snapshots);
			commit = true;
		}
		finally {
			currentProgram.endTransaction(tx, commit);
		}

		println("Selection range: " + start + " - " + end);
		println("Original block: " + originalBlock.getName());
		println("Converted to uninitialized: " + convertedToUninitialized);
		println("Captured and restored " + snapshots.size() + " top-level data definition(s).");
	}

	private boolean validateSupportedBlock(MemoryBlock block) {
		if (!block.isInitialized()) {
			printerr("Selected block is already uninitialized. This script targets initialized .data-like blocks.");
			return false;
		}

		if (block.isExecute()) {
			printerr("Selected block is executable. This script targets non-executable .data-like blocks.");
			return false;
		}

		if (!block.isWrite()) {
			printerr("Selected block is not writable. This script targets writable .data-like RAM blocks.");
			return false;
		}

		return true;
	}

	private List<DataSnapshot> snapshotDefinedData(Listing listing, AddressSetView selection) {
		List<DataSnapshot> snapshots = new ArrayList<>();
		DataIterator it = listing.getDefinedData(selection, true);
		while (it.hasNext() && !monitor.isCancelled()) {
			Data data = it.next();
			if (data.getParent() != null) {
				continue;
			}

			DataType dt = data.getDataType();
			if (dt == null) {
				continue;
			}

			snapshots.add(new DataSnapshot(data.getAddress(), dt, data.getLength()));
		}

		snapshots.sort(Comparator.comparing(DataSnapshot::address));
		return snapshots;
	}

	private MemoryBlock isolateSelectedBlock(Memory memory, MemoryBlock block, Address start,
			Address end) throws MemoryBlockException, LockException {
		MemoryBlock current = block;

		if (!current.getStart().equals(start)) {
			splitBlock(memory, current, start);
			current = memory.getBlock(start);
		}

		Address afterEnd = end.next();
		if (afterEnd != null && current.contains(afterEnd)) {
			splitBlock(memory, current, afterEnd);
			current = memory.getBlock(start);
		}

		if (current == null || !current.getStart().equals(start) || !current.getEnd().equals(end)) {
			throw new IllegalStateException(
				"Failed to isolate the selected range into its own memory block.");
		}

		return current;
	}

	private void splitBlock(Memory memory, MemoryBlock block, Address splitAddress)
			throws MemoryBlockException, LockException {
		try {
			memory.split(block, splitAddress);
		}
		catch (LockException e) {
			throw new LockException("Failed to split block '" + block.getName() +
				"' at " + splitAddress + " due to lock contention: " + e.getMessage());
		}
		catch (MemoryBlockException e) {
			throw new MemoryBlockException("Failed to split block '" + block.getName() +
				"' at " + splitAddress + ": " + e.getMessage());
		}
	}

	private void restoreDefinedData(Listing listing, Address start, Address end,
			List<DataSnapshot> snapshots) {
		listing.clearCodeUnits(start, end, false);

		int restored = 0;
		int failed = 0;
		for (DataSnapshot snapshot : snapshots) {
			if (monitor.isCancelled()) {
				break;
			}

			try {
				// FlatProgramAPI in this scripting environment exposes only
				// createData(Address, DataType).
				createData(snapshot.address(), snapshot.dataType());
				restored++;
			}
			catch (Exception e) {
				failed++;
				printerr("Failed to restore data at " + snapshot.address() + " as " +
					snapshot.dataType().getName() + " (snapshot length=" +
					snapshot.length() + "): " + e.getMessage());
			}
		}

		println("Restored data definitions: " + restored + ", failed: " + failed);
	}
}
