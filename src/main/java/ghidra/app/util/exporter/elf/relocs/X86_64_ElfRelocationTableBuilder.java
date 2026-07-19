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
import ghidra.program.model.relocobj.RelocationEntry;
import ghidra.program.model.relocobj.RelocationExpressionKind;
import ghidra.program.model.relocobj.RelocationGang;
import ghidra.program.model.relocobj.RelocationGroup;
import ghidra.util.DataConverter;
import net.boricj.bft.elf.ElfFile;
import net.boricj.bft.elf.ElfHeader;
import net.boricj.bft.elf.ElfSection;
import net.boricj.bft.elf.constants.ElfClass;
import net.boricj.bft.elf.constants.ElfData;
import net.boricj.bft.elf.constants.ElfMachine;
import net.boricj.bft.elf.constants.ElfRelocationType;
import net.boricj.bft.elf.constants.ElfSectionNames;
import net.boricj.bft.elf.constants.ElfSectionType;
import net.boricj.bft.elf.machines.amd64.ElfRelocationType_amd64;
import net.boricj.bft.elf.sections.ElfRelaTable;
import net.boricj.bft.elf.sections.ElfSymbolTable;
import net.boricj.bft.elf.sections.ElfSymbolTable.ElfSymbol;

public class X86_64_ElfRelocationTableBuilder implements ElfRelocationTableBuilder {
	public boolean supportsGroupedRelocations() {
		return true;
	}

	@Override
	public ElfSection buildGroups(ElfFile elf, ElfSymbolTable symtab, ElfSection section,
			byte[] bytes, AddressSetView addressSetView, List<RelocationGroup> groups,
			Map<RelocationGroup, ElfSymbol> groupsToSymbols, MessageLog log) {
		String relName = generateSectionName(section, ElfSectionNames._RELA);
		ElfRelaTable relTable = new ElfRelaTable(elf, relName, symtab, section);

		for (RelocationGroup group : groups) {
			ElfSymbol symbol = groupsToSymbols.get(group);
			for (RelocationGang gang : group.getGangs()) {
				for (RelocationEntry entry : gang.getEntries()) {
					process(relTable, bytes, addressSetView, group, gang, entry, symbol, log);
				}
			}
		}

		return relTable;
	}

	private void process(ElfRelaTable relTable, byte[] bytes, AddressSetView addressSetView,
			RelocationGroup group, RelocationGang gang, RelocationEntry entry, ElfSymbol symbol,
			MessageLog log) {
		DataConverter dc = DataConverter.getInstance(
			relTable.getElfFile().getHeader().getIdentData() == ElfData.ELFDATA2MSB);
		int width = gang.getWidth();
		long bitmask = gang.getBitmask();
		long value = group.getAddend() + entry.localAddend();

		RelocationExpressionKind kind = group.getExpression().getKind();
		ElfRelocationType type = null;
		if (kind == RelocationExpressionKind.ABSOLUTE) {
			if (width == 4 && bitmask == 0xffffffffL) {
				type = ElfRelocationType_amd64.R_X86_64_32S;
			}
			else if (width == 8 && bitmask == 0xffffffffffffffffL) {
				type = ElfRelocationType_amd64.R_X86_64_64;
			}
		}
		else if (kind == RelocationExpressionKind.PC_RELATIVE) {
			if (width == 4 && bitmask == 0xffffffffL) {
				type = ElfRelocationType_amd64.R_X86_64_PC32;
			}
			else if (width == 8 && bitmask == 0xffffffffffffffffL) {
				type = ElfRelocationType_amd64.R_X86_64_PC64;
			}
		}

		if (type == null) {
			logUnknownRelocation(relTable, group, gang, entry, log);
			return;
		}

		patchBytes(bytes, addressSetView, entry.address(), dc, width, bitmask, 0);
		emit(relTable, addressSetView, entry.address(), type, symbol, value);
	}

	private void emit(ElfRelaTable relTable, AddressSetView addressSetView,
			ghidra.program.model.address.Address address, ElfRelocationType type, ElfSymbol symbol,
			long addend) {
		long offset = getOffsetWithinAddressSet(addressSetView, address);

		relTable.add(offset, symbol, type, addend);
	}

	@Override
	public boolean canBuild(ElfFile elf, ElfSectionType sectionType) {
		ElfHeader header = elf.getHeader();
		return header.getMachine() == ElfMachine.EM_X86_64 &&
			header.getIdentClass() == ElfClass.ELFCLASS64 &&
			sectionType == ElfSectionType.SHT_RELA;
	}
}
