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

import static ghidra.app.analyzers.relocations.MipsCodeRelocationSynthesizer.GP_SYMBOLS_PATTERN;
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
import ghidra.program.model.relocobj.RelocationTypeTag;
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
	public boolean supportsGroupedRelocations() {
		return true;
	}

	@Override
	public ElfSection buildGroups(ElfFile elf, ElfSymbolTable symtab, ElfSection section,
			byte[] bytes, AddressSetView addressSetView, List<RelocationGroup> groups,
			Map<RelocationGroup, ElfSymbol> groupsToSymbols, MessageLog log) {
		String relName = generateSectionName(section, ElfSectionNames._REL);
		ElfRelTable relTable = new ElfRelTable(elf, relName, symtab, section);

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

	private void process(ElfRelTable relTable, byte[] bytes, AddressSetView addressSetView,
			RelocationGroup group, RelocationGang gang, RelocationEntry entry, ElfSymbol symbol,
			MessageLog log) {
		DataConverter dc = DataConverter.getInstance(
			relTable.getElfFile().getHeader().getIdentData() == ElfData.ELFDATA2MSB);
		int width = gang.getWidth();
		long bitmask = gang.getBitmask();
		long value = group.getAddend() + entry.localAddend();

		RelocationTypeTag relocationType = gang.getRelocationType();
		RelocationExpressionKind kind = group.getExpression().getKind();
		ElfRelocationType type = null;

		if (relocationType == RelocationTypeTag.HIGH_PAIR) {
			if (width == 4 && bitmask == 0xffff) {
				type = ElfRelocationType_Mips.R_MIPS_HI16;
			}
		}
		else if (relocationType == RelocationTypeTag.LOW_PAIR) {
			if (width == 4 && bitmask == 0xffff) {
				type = ElfRelocationType_Mips.R_MIPS_LO16;
			}
		}
		else if (relocationType == RelocationTypeTag.MIPS_26) {
			if (width == 4 && bitmask == 0x3ffffff) {
				type = ElfRelocationType_Mips.R_MIPS_26;
				value >>= 2;
			}
		}
		else if (kind == RelocationExpressionKind.RELATIVE_TO_SYMBOL &&
				group.getExpression().getSymbolName() != null &&
				GP_SYMBOLS_PATTERN.matcher(group.getExpression().getSymbolName()).matches()) {
			if (width == 4 && bitmask == 0xffff) {
				type = ElfRelocationType_Mips.R_MIPS_GPREL16;
			}
		}
		else if (kind == RelocationExpressionKind.PC_RELATIVE) {
			if (width == 4 && bitmask == 0xffff) {
				type = ElfRelocationType_Mips.R_MIPS_PC16;
				value >>= 2;
			}
		}
		else if (kind == RelocationExpressionKind.ABSOLUTE) {
			if (width == 4 && bitmask == 0xffffffffL) {
				type = ElfRelocationType_Mips.R_MIPS_32;
			}
			else if (width == 8 && bitmask == 0xffffffffffffffffL) {
				type = ElfRelocationType_Mips.R_MIPS_64;
			}
		}

		if (type == null) {
			logUnknownRelocation(relTable, group, gang, entry, log);
			return;
		}

		patchBytes(bytes, addressSetView, entry.address(), dc, width, bitmask, value);
		emit(relTable, addressSetView, entry.address(), type, symbol);
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
