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
import ghidra.program.model.relocobj.RelocationExpressionKind;
import ghidra.program.model.relocobj.RelocationGang;
import ghidra.program.model.relocobj.RelocationGroup;
import ghidra.program.model.relocobj.RelocationTypeTag;
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
			for (RelocationGang gang : group.getGangs()) {
				for (RelocationEntry entry : gang.getEntries()) {
					process(relTable, bytes, addressSet, group, gang, entry, symbol, log);
				}
			}
		}
	}

	private void process(CoffRelocationTable relTable, byte[] bytes,
			AddressSetView addressSet, RelocationGroup group, RelocationGang gang,
			RelocationEntry entry, CoffSymbol symbol, MessageLog log) {
		DataConverter dc = DataConverter.getInstance(true);
		int width = gang.getWidth();
		long bitmask = gang.getBitmask();
		long addend = group.getAddend() + entry.localAddend();
		long offset = getOffsetWithinAddressSet(addressSet, entry.address());

		RelocationTypeTag relocationType = gang.getRelocationType();
		RelocationExpressionKind kind = group.getExpression().getKind();
		CoffRelocationType type = null;
		long value;
		boolean emitPair = false;

		if (relocationType == RelocationTypeTag.HIGH_PAIR) {
			if (width == 4 && bitmask == 0xffffL) {
				type = CoffRelocationType_ppc.IMAGE_REL_PPC_REFHI;
				emitPair = true;
			}
			value = addend;
		}
		else if (relocationType == RelocationTypeTag.LOW_PAIR) {
			if (width == 4 && bitmask == 0xffffL) {
				type = CoffRelocationType_ppc.IMAGE_REL_PPC_REFLO;
				emitPair = true;
			}
			value = addend;
		}
		else if (kind == RelocationExpressionKind.PC_RELATIVE) {
			if (width == 4 && bitmask == 0x03fffffcL) {
				type = CoffRelocationType_ppc.IMAGE_REL_PPC_REL24;
			}
			else if (width == 4 && bitmask == 0x0000fffcL) {
				type = CoffRelocationType_ppc.IMAGE_REL_PPC_REL14;
			}
			value = (addend - offset) >> 2;
		}
		else {
			if (width == 4 && bitmask == 0xffffffffL) {
				type = CoffRelocationType_ppc.IMAGE_REL_PPC_ADDR32;
			}
			value = addend;
		}

		if (type == null) {
			logUnknownRelocation(relTable.getSection(), group, gang, entry, log);
			return;
		}

		patchBytes(bytes, addressSet, entry.address(), dc, width, bitmask, value);
		emit(relTable, addressSet, entry.address(), type, symbol);
		if (emitPair) {
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
