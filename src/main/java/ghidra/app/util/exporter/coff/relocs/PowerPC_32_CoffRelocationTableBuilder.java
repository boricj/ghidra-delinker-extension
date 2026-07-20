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
package ghidra.app.util.exporter.coff.relocs;

import static ghidra.app.util.ProgramUtil.getOffsetWithinAddressSet;
import static ghidra.app.util.ProgramUtil.patchBytes;
import static ghidra.app.util.exporter.coff.relocs.CoffRelocationTableBuilder.logUnknownRelocation;

import java.util.List;
import java.util.Map;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.relocobj.RelocationEntry;
import ghidra.program.model.relocobj.RelocationGang;
import ghidra.program.model.relocobj.RelocationGroup;
import ghidra.util.DataConverter;
import net.boricj.bft.coff.CoffRelocationTable;
import net.boricj.bft.coff.CoffSection;
import net.boricj.bft.coff.CoffSymbolTable;
import net.boricj.bft.coff.CoffSymbolTable.CoffSymbol;
import net.boricj.bft.coff.constants.CoffMachine;
import net.boricj.bft.coff.constants.CoffRelocationType;
import net.boricj.bft.coff.machines.ppc.CoffRelocationType_ppc;

public class PowerPC_32_CoffRelocationTableBuilder implements CoffRelocationTableBuilder {
	public boolean supportsGroupedRelocations() {
		return true;
	}

	@Override
	public void buildGroups(CoffSymbolTable symtab, CoffSection section, byte[] bytes,
			AddressSetView addressSet, List<RelocationGroup> groups,
			Map<RelocationGroup, CoffSymbol> groupsToSymbols, MessageLog log) {
		CoffRelocationTable relTable = section.getRelocations();

		for (RelocationGroup group : groups) {
			CoffSymbol symbol = groupsToSymbols.get(group);
			for (int gangIndex = 0; gangIndex < group.getGangs().size(); gangIndex++) {
				RelocationGang gang = group.getGangs().get(gangIndex);
				for (RelocationEntry entry : gang.getEntries()) {
					process(relTable, bytes, addressSet, group, gang, gangIndex, entry,
						symbol, log);
				}
			}
		}
	}

	private void process(CoffRelocationTable relTable, byte[] bytes,
			AddressSetView addressSet, RelocationGroup group, RelocationGang gang,
			int gangIndex, RelocationEntry entry, CoffSymbol symbol, MessageLog log) {
		DataConverter dc = DataConverter.getInstance(true);
		int width = gang.getWidth();
		long bitmask = gang.getBitmask();
		long addend = group.getAddend() + entry.localAddend();
		long offset = getOffsetWithinAddressSet(addressSet, entry.address());

		PowerPCRelocationTableLowering.Result lowering =
			PowerPCRelocationTableLowering.tryLower(group, gang, gangIndex, addend, offset);
		if (lowering == null) {
			logUnknownRelocation(relTable.getSection(), group, gang, entry, log);
			return;
		}

		patchBytes(bytes, addressSet, entry.address(), dc, width, bitmask, lowering.value());
		emit(relTable, addressSet, entry.address(), lowering.type(), symbol);
		if (lowering.emitPair()) {
			emitPair(relTable, addressSet, entry.address());
		}
	}

	private void emit(CoffRelocationTable relTable, AddressSetView addressSetView,
			ghidra.program.model.address.Address address, CoffRelocationType type, CoffSymbol symbol) {
		int offset = (int) getOffsetWithinAddressSet(addressSetView, address);
		relTable.add(offset, symbol, type);
	}

	private void emitPair(CoffRelocationTable relTable, AddressSetView addressSetView,
			ghidra.program.model.address.Address address) {
		int offset = (int) getOffsetWithinAddressSet(addressSetView, address);
		relTable.add(offset, 0, CoffRelocationType_ppc.IMAGE_REL_PPC_PAIR);
	}

	@Override
	public boolean canBuild(CoffMachine machine) {
		return machine == CoffMachine.IMAGE_FILE_MACHINE_POWERPCBE;
	}
}
