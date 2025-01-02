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
import ghidra.program.model.relocobj.Relocation;
import ghidra.program.model.relocobj.RelocationAbsolute;
import ghidra.program.model.relocobj.RelocationHighPair;
import ghidra.program.model.relocobj.RelocationLowPair;
import ghidra.program.model.relocobj.RelocationMIPS26;
import ghidra.program.model.relocobj.RelocationRelativePC;
import ghidra.program.model.relocobj.RelocationRelativeSymbol;
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
	@Override
	public ElfSection build(ElfFile elf, ElfSymbolTable symtab, ElfSection section, byte[] bytes,
			AddressSetView addressSetView, List<Relocation> relocations,
			Map<Relocation, ElfSymbol> relocationsToSymbols, MessageLog log) {
		String relName = generateSectionName(section, ElfSectionNames._REL);
		ElfRelTable relTable = new ElfRelTable(elf, relName, symtab, section);

		for (Relocation relocation : relocations) {
			ElfSymbol symbol = relocationsToSymbols.get(relocation);

			if (relocation instanceof RelocationAbsolute) {
				process(relTable, bytes, addressSetView, (RelocationAbsolute) relocation, symbol,
					log);
			}
			else if (relocation instanceof RelocationHighPair) {
				RelocationHighPair highPair = (RelocationHighPair) relocation;
				process(relTable, bytes, addressSetView, highPair, symbol, log);

				for (RelocationLowPair lowPair : highPair.getLowPairs()) {
					process(relTable, bytes, addressSetView, lowPair, symbol, log);
				}
			}
			else if (relocation instanceof RelocationLowPair) {
				// Low pairs are processed by their high pair.
				continue;
			}
			else if (relocation instanceof RelocationRelativePC) {
				process(relTable, bytes, addressSetView, (RelocationRelativePC) relocation, symbol,
					log);
			}
			else if (relocation instanceof RelocationRelativeSymbol) {
				process(relTable, bytes, addressSetView, (RelocationRelativeSymbol) relocation,
					symbol, log);
			}
			else if (relocation instanceof RelocationMIPS26) {
				process(relTable, bytes, addressSetView, (RelocationMIPS26) relocation, symbol,
					log);
			}
			else {
				logUnknownRelocation(section, relocation, log);
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
			type = ElfRelocationType_Mips.R_MIPS_32;
		}
		else if (width == 8 && bitmask == 0xffffffffffffffffL) {
			type = ElfRelocationType_Mips.R_MIPS_64;
		}
		else {
			logUnknownRelocation(relTable, relocation, log);
			return;
		}

		patchBytes(bytes, addressSetView, dc, relocation, value);
		emit(relTable, addressSetView, relocation, type, symbol);
	}

	private void process(ElfRelTable relTable, byte[] bytes,
			AddressSetView addressSetView, RelocationHighPair relocation,
			ElfSymbol symbol, MessageLog log) {
		DataConverter dc = DataConverter.getInstance(
			relTable.getElfFile().getHeader().getIdentData() == ElfData.ELFDATA2MSB);
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long value = relocation.getAddend();

		ElfRelocationType type;
		if (width == 4 && bitmask == 0xffff) {
			type = ElfRelocationType_Mips.R_MIPS_HI16;
		}
		else {
			logUnknownRelocation(relTable, relocation, log);
			return;
		}

		patchBytes(bytes, addressSetView, dc, relocation, value);
		emit(relTable, addressSetView, relocation, type, symbol);
	}

	private void process(ElfRelTable relTable, byte[] bytes, AddressSetView addressSetView,
			RelocationLowPair relocation, ElfSymbol symbol, MessageLog log) {
		DataConverter dc = DataConverter.getInstance(
			relTable.getElfFile().getHeader().getIdentData() == ElfData.ELFDATA2MSB);
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long value = relocation.getAddend();

		ElfRelocationType type;
		if (width == 4 && bitmask == 0xffff) {
			type = ElfRelocationType_Mips.R_MIPS_LO16;
		}
		else {
			logUnknownRelocation(relTable, relocation, log);
			return;
		}

		patchBytes(bytes, addressSetView, dc, relocation, value);
		emit(relTable, addressSetView, relocation, type, symbol);
	}

	private void process(ElfRelTable relTable, byte[] bytes, AddressSetView addressSetView,
			RelocationRelativeSymbol relocation, ElfSymbol symbol, MessageLog log) {
		DataConverter dc = DataConverter.getInstance(
			relTable.getElfFile().getHeader().getIdentData() == ElfData.ELFDATA2MSB);
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long value = relocation.getAddend();
		String symbolName = relocation.getRelativeSymbolName();

		ElfRelocationType type;
		if (width == 4 && bitmask == 0xffff && GP_SYMBOLS_PATTERN.matcher(symbolName).matches()) {
			type = ElfRelocationType_Mips.R_MIPS_GPREL16;
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
		long value = relocation.getAddend() >> 2;

		ElfRelocationType type;
		if (width == 4 && bitmask == 0xffff) {
			type = ElfRelocationType_Mips.R_MIPS_PC16;
		}
		else {
			logUnknownRelocation(relTable, relocation, log);
			return;
		}

		patchBytes(bytes, addressSetView, dc, relocation, value);
		emit(relTable, addressSetView, relocation, type, symbol);
	}

	private void process(ElfRelTable relTable, byte[] bytes, AddressSetView addressSetView,
			RelocationMIPS26 relocation, ElfSymbol symbol, MessageLog log) {
		DataConverter dc = DataConverter.getInstance(
			relTable.getElfFile().getHeader().getIdentData() == ElfData.ELFDATA2MSB);
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long value = relocation.getAddend() >> 2;

		ElfRelocationType type;
		if (width == 4 && bitmask == 0x3ffffff) {
			type = ElfRelocationType_Mips.R_MIPS_26;
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
		return header.getMachine() == ElfMachine.EM_MIPS &&
			sectionType == ElfSectionType.SHT_REL;
	}
}
