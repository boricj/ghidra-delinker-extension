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
package ghidra.app.util.exporter.elf.relocs;

import static ghidra.app.util.ProgramUtil.getOffsetWithinAddressSet;
import static ghidra.app.util.ProgramUtil.patchBytes;
import static ghidra.app.util.exporter.elf.relocs.ElfRelocationTableBuilder.generateSectionName;
import static ghidra.app.util.exporter.elf.relocs.ElfRelocationTableBuilder.logUnknownRelocation;

import java.util.List;
import java.util.Map;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.relocobj.RelocationExpressionBase;
import ghidra.program.model.relocobj.RelocationExpressionKind;
import ghidra.program.model.relocobj.RelocationEntry;
import ghidra.program.model.relocobj.RelocationGang;
import ghidra.program.model.relocobj.RelocationGroup;
import ghidra.util.DataConverter;
import net.boricj.bft.elf.ElfFile;
import net.boricj.bft.elf.ElfHeader;
import net.boricj.bft.elf.ElfSection;
import net.boricj.bft.elf.constants.ElfData;
import net.boricj.bft.elf.constants.ElfMachine;
import net.boricj.bft.elf.constants.ElfRelocationType;
import net.boricj.bft.elf.constants.ElfSectionNames;
import net.boricj.bft.elf.constants.ElfSectionType;
import net.boricj.bft.elf.machines.mips.ElfRelocationType_Mips;
import net.boricj.bft.elf.sections.ElfRelTable;
import net.boricj.bft.elf.sections.ElfSymbolTable;
import net.boricj.bft.elf.sections.ElfSymbolTable.ElfSymbol;

public class Mips_ElfRelocationTableBuilder implements ElfRelocationTableBuilder {
	private static final class BuildState {
		private final ElfRelTable relTable;
		private final byte[] bytes;
		private final AddressSetView addressSetView;
		private final DataConverter dataConverter;
		private final MessageLog log;

		private BuildState(ElfRelTable relTable, byte[] bytes,
				AddressSetView addressSetView, DataConverter dataConverter, MessageLog log) {
			this.relTable = relTable;
			this.bytes = bytes;
			this.addressSetView = addressSetView;
			this.dataConverter = dataConverter;
			this.log = log;
		}
	}

	public boolean supportsGroupedRelocations() {
		return true;
	}

	@Override
	public ElfSection buildGroups(ElfFile elf, ElfSymbolTable symtab, ElfSection section,
			byte[] bytes, AddressSetView addressSetView, List<RelocationGroup> groups,
			Map<RelocationGroup, ElfSymbol> groupsToSymbols, MessageLog log) {
		String relName = generateSectionName(section, ElfSectionNames._REL);
		ElfRelTable relTable = new ElfRelTable(elf, relName, symtab, section);
		BuildState state = new BuildState(relTable, bytes, addressSetView,
			DataConverter.getInstance(
				relTable.getElfFile().getHeader().getIdentData() == ElfData.ELFDATA2MSB),
			log);

		for (RelocationGroup group : groups) {
			processGroup(state, group, groupsToSymbols.get(group));
		}

		return relTable;
	}

	private void processGroup(BuildState state, RelocationGroup group, ElfSymbol symbol) {
		RelocationExpressionKind kind = group.getExpression().getKind();
		RelocationExpressionBase base = group.getExpression().getBase();

		if (kind == RelocationExpressionKind.SYMBOL_RELATIVE &&
			base == RelocationExpressionBase.GP) {
			for (int gangIndex = 0; gangIndex < group.getGangs().size(); gangIndex++) {
				RelocationGang gang = group.getGangs().get(gangIndex);
				for (RelocationEntry entry : gang.getEntries()) {
					processEntryGpRelative(state, group, gang, gangIndex, entry, symbol);
				}
			}
			return;
		}
		if (kind == RelocationExpressionKind.REGION_RELATIVE) {
			for (int gangIndex = 0; gangIndex < group.getGangs().size(); gangIndex++) {
				RelocationGang gang = group.getGangs().get(gangIndex);
				for (RelocationEntry entry : gang.getEntries()) {
					processEntryRegionRelative(state, group, gang, gangIndex, entry, symbol);
				}
			}
			return;
		}
		if (kind == RelocationExpressionKind.PC_RELATIVE) {
			for (int gangIndex = 0; gangIndex < group.getGangs().size(); gangIndex++) {
				RelocationGang gang = group.getGangs().get(gangIndex);
				for (RelocationEntry entry : gang.getEntries()) {
					processEntryPcRelative(state, group, gang, gangIndex, entry, symbol);
				}
			}
			return;
		}
		if (kind == RelocationExpressionKind.ABSOLUTE) {
			for (int gangIndex = 0; gangIndex < group.getGangs().size(); gangIndex++) {
				RelocationGang gang = group.getGangs().get(gangIndex);
				processGangAbsolute(state, group, gang, gangIndex, symbol);
			}
			return;
		}

		processGroupUnknown(state, group, symbol);
	}

	private void processGroupUnknown(BuildState state, RelocationGroup group, ElfSymbol symbol) {
		for (RelocationGang gang : group.getGangs()) {
			for (RelocationEntry entry : gang.getEntries()) {
				logUnknownRelocation(state.relTable, group, gang, entry, state.log);
			}
		}
	}

	private void processGangAbsolute(BuildState state, RelocationGroup group, RelocationGang gang,
			int gangIndex, ElfSymbol symbol) {
		if (isPairShape(group, gang)) {
			for (RelocationEntry entry : gang.getEntries()) {
				processEntryAbsolutePair(state, group, gang, gangIndex, entry, symbol);
			}
			return;
		}

		for (RelocationEntry entry : gang.getEntries()) {
			processEntryAbsoluteScalar(state, group, gang, gangIndex, entry, symbol);
		}
	}

	private void processEntryAbsolutePair(BuildState state, RelocationGroup group,
			RelocationGang gang, int gangIndex, RelocationEntry entry, ElfSymbol symbol) {
		int width = gang.getWidth();
		long bitmask = gang.getBitmask();
		long value = group.getAddend() + entry.localAddend();

		ElfRelocationType type = null;
		if (gangIndex == 0) {
			type = ElfRelocationType_Mips.R_MIPS_HI16;
		}
		else if (gangIndex == 1) {
			type = ElfRelocationType_Mips.R_MIPS_LO16;
		}

		if (type == null) {
			logUnknownRelocation(state.relTable, group, gang, entry, state.log);
			return;
		}

		patchBytes(state.bytes, state.addressSetView, entry.address(), state.dataConverter,
			width, bitmask, value);
		emit(state.relTable, state.addressSetView, entry.address(), type, symbol);
	}

	private void processEntryAbsoluteScalar(BuildState state, RelocationGroup group,
			RelocationGang gang, int gangIndex, RelocationEntry entry, ElfSymbol symbol) {
		int width = gang.getWidth();
		long bitmask = gang.getBitmask();
		long value = group.getAddend() + entry.localAddend();
		ElfRelocationType type = null;

		if (width == 4 && bitmask == 0xffffffffL) {
			type = ElfRelocationType_Mips.R_MIPS_32;
		}
		else if (width == 8 && bitmask == 0xffffffffffffffffL) {
			type = ElfRelocationType_Mips.R_MIPS_64;
		}

		if (type == null) {
			logUnknownRelocation(state.relTable, group, gang, entry, state.log);
			return;
		}

		patchBytes(state.bytes, state.addressSetView, entry.address(), state.dataConverter,
			width, bitmask, value);
		emit(state.relTable, state.addressSetView, entry.address(), type, symbol);
	}

	private void processEntryRegionRelative(BuildState state, RelocationGroup group,
			RelocationGang gang, int gangIndex, RelocationEntry entry, ElfSymbol symbol) {
		int width = gang.getWidth();
		long bitmask = gang.getBitmask();
		long value = group.getAddend() + entry.localAddend();

		if (width == 4 && bitmask == 0x3ffffff) {
			value >>= 2;
			patchBytes(state.bytes, state.addressSetView, entry.address(), state.dataConverter,
				width, bitmask, value);
			emit(state.relTable, state.addressSetView, entry.address(),
				ElfRelocationType_Mips.R_MIPS_26, symbol);
			return;
		}

		logUnknownRelocation(state.relTable, group, gang, entry, state.log);
	}

	private void processEntryPcRelative(BuildState state, RelocationGroup group,
			RelocationGang gang, int gangIndex, RelocationEntry entry, ElfSymbol symbol) {
		int width = gang.getWidth();
		long bitmask = gang.getBitmask();
		long value = group.getAddend() + entry.localAddend();

		if (width == 4 && bitmask == 0xffff) {
			value >>= 2;
			patchBytes(state.bytes, state.addressSetView, entry.address(), state.dataConverter,
				width, bitmask, value);
			emit(state.relTable, state.addressSetView, entry.address(),
				ElfRelocationType_Mips.R_MIPS_PC16, symbol);
			return;
		}

		logUnknownRelocation(state.relTable, group, gang, entry, state.log);
	}

	private void processEntryGpRelative(BuildState state, RelocationGroup group,
			RelocationGang gang, int gangIndex, RelocationEntry entry, ElfSymbol symbol) {
		int width = gang.getWidth();
		long bitmask = gang.getBitmask();
		long value = group.getAddend() + entry.localAddend();

		if (width == 4 && bitmask == 0xffff) {
			patchBytes(state.bytes, state.addressSetView, entry.address(), state.dataConverter,
				width, bitmask, value);
			emit(state.relTable, state.addressSetView, entry.address(),
				ElfRelocationType_Mips.R_MIPS_GPREL16, symbol);
			return;
		}

		logUnknownRelocation(state.relTable, group, gang, entry, state.log);
	}

	private static boolean isPairShape(RelocationGroup group, RelocationGang gang) {
		return group.getGangs().size() == 2 && gang.getWidth() == 4 && gang.getBitmask() == 0xffffL;
	}

	private void emit(ElfRelTable relTable, AddressSetView addressSetView,
			ghidra.program.model.address.Address address, ElfRelocationType type, ElfSymbol symbol) {
		long offset = getOffsetWithinAddressSet(addressSetView, address);
		relTable.add(offset, symbol, type);
	}

	@Override
	public boolean canBuild(ElfFile elf, ElfSectionType sectionType) {
		ElfHeader header = elf.getHeader();
		return header.getMachine() == ElfMachine.EM_MIPS &&
			sectionType == ElfSectionType.SHT_REL;
	}
}
