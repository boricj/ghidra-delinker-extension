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
import ghidra.program.model.relocobj.Relocation;
import ghidra.program.model.relocobj.RelocationAbsolute;
import ghidra.program.model.relocobj.RelocationRelativePC;
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
import net.boricj.bft.elf.machines.i386.ElfRelocationType_i386;
import net.boricj.bft.elf.sections.ElfRelTable;
import net.boricj.bft.elf.sections.ElfSymbolTable;
import net.boricj.bft.elf.sections.ElfSymbolTable.ElfSymbol;

public class X86_32_ElfRelocationTableBuilder implements ElfRelocationTableBuilder {
	@Override
	public ElfSection build(ElfFile elf, ElfSymbolTable symtab, ElfSection section, byte[] bytes,
			AddressSetView addressSetView, List<Relocation> relocations,
			Map<String, ElfSymbol> symbolsByName, MessageLog log) {
		String relName = generateSectionName(section, ElfSectionNames._REL);
		ElfRelTable relTable =
			new ElfRelTable(elf, relName, symtab, section);

		for (Relocation relocation : relocations) {
			ElfSymbol symbol = symbolsByName.get(relocation.getSymbolName());

			if (relocation instanceof RelocationAbsolute) {
				process(relTable, bytes, addressSetView, (RelocationAbsolute) relocation, symbol,
					log);
			}
			else if (relocation instanceof RelocationRelativePC) {
				process(relTable, bytes, addressSetView, (RelocationRelativePC) relocation, symbol,
					log);
			}
			else {
				logUnknownRelocation(relTable, relocation, log);
			}
		}

		return relTable;
	}

	private void process(ElfRelTable relTable, byte[] bytes, AddressSetView addressSetView,
			RelocationAbsolute relocation, ElfSymbol symbol, MessageLog log) {
		DataConverter dc = DataConverter.getInstance(
			relTable.getElfFile().getHeader().getIdentData() == ElfData.ELFDATA2MSB);
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long value = relocation.getAddend();

		ElfRelocationType type;
		if (width == 4 && bitmask == 0xffffffffL) {
			type = ElfRelocationType_i386.R_386_32;
		}
		else {
			logUnknownRelocation(relTable, relocation, log);
			return;
		}

		patchBytes(bytes, addressSetView, dc, relocation, value);
		emit(relTable, addressSetView, relocation, type, symbol);
	}

	private void process(ElfRelTable relTable, byte[] bytes, AddressSetView addressSetView,
			RelocationRelativePC relocation, ElfSymbol symbol, MessageLog log) {
		DataConverter dc = DataConverter.getInstance(
			relTable.getElfFile().getHeader().getIdentData() == ElfData.ELFDATA2MSB);
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long value = relocation.getAddend();

		ElfRelocationType type;
		if (width == 4 && bitmask == 0xffffffffL) {
			type = ElfRelocationType_i386.R_386_PC32;
		}
		else {
			logUnknownRelocation(relTable, relocation, log);
			return;
		}

		patchBytes(bytes, addressSetView, dc, relocation, value);
		emit(relTable, addressSetView, relocation, type, symbol);
	}

	private void emit(ElfRelTable relTable, AddressSetView addressSetView, Relocation relocation,
			ElfRelocationType type, ElfSymbol symbol) {
		long offset = getOffsetWithinAddressSet(addressSetView, relocation.getAddress());

		relTable.add(offset, symbol, type);
	}

	@Override
	public boolean canBuild(ElfFile elf, ElfSectionType sectionType) {
		ElfHeader header = elf.getHeader();
		return header.getMachine() == ElfMachine.EM_386 &&
			header.getIdentClass() == ElfClass.ELFCLASS32 &&
			sectionType == ElfSectionType.SHT_REL;
	}
}
