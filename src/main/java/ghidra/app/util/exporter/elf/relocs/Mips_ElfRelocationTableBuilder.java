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
import static ghidra.app.util.ProgramUtil.patchBytes;
import static ghidra.app.util.exporter.elf.relocs.ElfRelocationTableBuilder.generateSectionName;
import static ghidra.app.util.exporter.elf.relocs.ElfRelocationTableBuilder.logUnknownRelocation;

import java.util.List;

import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.bin.format.elf.relocation.MIPS_ElfRelocationType;
import ghidra.app.util.exporter.elf.ElfRelocatableObject;
import ghidra.app.util.exporter.elf.ElfRelocatableSection;
import ghidra.app.util.exporter.elf.ElfRelocatableSectionRelTable;
import ghidra.app.util.exporter.elf.ElfRelocatableSectionSymbolTable;
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

public class Mips_ElfRelocationTableBuilder implements ElfRelocationTableBuilder {
	@Override
	public ElfRelocatableSection build(ElfRelocatableObject elf,
			ElfRelocatableSectionSymbolTable symtab, ElfRelocatableSection section, byte[] bytes,
			AddressSetView addressSet,
			List<Relocation> relocations, MessageLog log) {
		String relName = generateSectionName(section, ".rel");
		ElfRelocatableSectionRelTable relTable =
			new ElfRelocatableSectionRelTable(elf, relName, symtab, section);

		for (Relocation relocation : relocations) {
			if (relocation instanceof RelocationAbsolute) {
				process(relTable, bytes, addressSet, (RelocationAbsolute) relocation, log);
			}
			else if (relocation instanceof RelocationHighPair) {
				RelocationHighPair highPair = (RelocationHighPair) relocation;
				process(relTable, bytes, addressSet, highPair, log);

				for (RelocationLowPair lowPair : highPair.getLowPairs()) {
					process(relTable, bytes, addressSet, lowPair, log);
				}
			}
			else if (relocation instanceof RelocationLowPair) {
				// Low pairs are processed by their high pair.
				continue;
			}
			else if (relocation instanceof RelocationRelativePC) {
				process(relTable, bytes, addressSet, (RelocationRelativePC) relocation, log);
			}
			else if (relocation instanceof RelocationRelativeSymbol) {
				process(relTable, bytes, addressSet, (RelocationRelativeSymbol) relocation, log);
			}
			else if (relocation instanceof RelocationMIPS26) {
				process(relTable, bytes, addressSet, (RelocationMIPS26) relocation, log);
			}
			else {
				logUnknownRelocation(section, relocation, log);
			}
		}

		return relTable;
	}

	private void process(ElfRelocatableSectionRelTable relTable, byte[] bytes,
			AddressSetView addressSet, RelocationAbsolute relocation,
			MessageLog log) {
		DataConverter dc = relTable.getElfRelocatableObject().getDataConverter();
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long value = relocation.getAddend();

		int type;
		if (width == 4 && bitmask == 0xffffffffL) {
			type = MIPS_ElfRelocationType.R_MIPS_32.typeId();
		}
		else {
			logUnknownRelocation(relTable, relocation, log);
			return;
		}

		patchBytes(bytes, addressSet, dc, relocation, value);
		emit(relTable, relocation, type);
	}

	private void process(ElfRelocatableSectionRelTable relTable, byte[] bytes,
			AddressSetView addressSet, RelocationHighPair relocation,
			MessageLog log) {
		DataConverter dc = relTable.getElfRelocatableObject().getDataConverter();
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long value = relocation.getAddend();

		int type;
		if (width == 4 && bitmask == 0xffff) {
			type = MIPS_ElfRelocationType.R_MIPS_HI16.typeId();
		}
		else {
			logUnknownRelocation(relTable, relocation, log);
			return;
		}

		patchBytes(bytes, addressSet, dc, relocation, value);
		emit(relTable, relocation, type);
	}

	private void process(ElfRelocatableSectionRelTable relTable, byte[] bytes,
			AddressSetView addressSet, RelocationLowPair relocation,
			MessageLog log) {
		DataConverter dc = relTable.getElfRelocatableObject().getDataConverter();
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long value = relocation.getAddend();

		int type;
		if (width == 4 && bitmask == 0xffff) {
			type = MIPS_ElfRelocationType.R_MIPS_LO16.typeId();
		}
		else {
			logUnknownRelocation(relTable, relocation, log);
			return;
		}

		patchBytes(bytes, addressSet, dc, relocation, value);
		emit(relTable, relocation, type);
	}

	private void process(ElfRelocatableSectionRelTable relTable, byte[] bytes,
			AddressSetView addressSet, RelocationRelativeSymbol relocation, MessageLog log) {
		DataConverter dc = relTable.getElfRelocatableObject().getDataConverter();
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long value = relocation.getAddend();
		String symbol = relocation.getRelativeSymbolName();

		int type;
		if (width == 4 && bitmask == 0xffff && GP_SYMBOLS_PATTERN.matcher(symbol).matches()) {
			type = MIPS_ElfRelocationType.R_MIPS_GPREL16.typeId();
		}
		else {
			logUnknownRelocation(relTable, relocation, log);
			return;
		}

		patchBytes(bytes, addressSet, dc, relocation, value);
		emit(relTable, relocation, type);
	}

	private void process(ElfRelocatableSectionRelTable relTable, byte[] bytes,
			AddressSetView addressSet, RelocationRelativePC relocation,
			MessageLog log) {
		DataConverter dc = relTable.getElfRelocatableObject().getDataConverter();
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long value = relocation.getAddend() >> 2;

		int type;
		if (width == 4 && bitmask == 0xffff) {
			type = MIPS_ElfRelocationType.R_MIPS_PC16.typeId();
		}
		else {
			logUnknownRelocation(relTable, relocation, log);
			return;
		}

		patchBytes(bytes, addressSet, dc, relocation, value);
		emit(relTable, relocation, type);
	}

	private void process(ElfRelocatableSectionRelTable relTable, byte[] bytes,
			AddressSetView addressSet, RelocationMIPS26 relocation,
			MessageLog log) {
		DataConverter dc = relTable.getElfRelocatableObject().getDataConverter();
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long value = relocation.getAddend() >> 2;

		int type;
		if (width == 4 && bitmask == 0x3ffffff) {
			type = MIPS_ElfRelocationType.R_MIPS_26.typeId();
		}
		else {
			logUnknownRelocation(relTable, relocation, log);
			return;
		}

		patchBytes(bytes, addressSet, dc, relocation, value);
		emit(relTable, relocation, type);
	}

	private void emit(ElfRelocatableSectionRelTable relTable, Relocation relocation, long type) {
		ElfRelocatableSection section = relTable.getSection();
		ElfRelocatableSectionSymbolTable symtab = relTable.getSymbolTable();

		long offset = section.getOffset(relocation.getAddress());
		long symindex = symtab.indexOf(symtab.get(relocation.getSymbolName()));

		relTable.add(offset, type, symindex);
	}

	@Override
	public boolean canBuild(ElfRelocatableObject elf, int sectionType) {
		return elf.getElfMachine() == ElfConstants.EM_MIPS &&
			sectionType == ElfSectionHeaderConstants.SHT_REL;
	}
}
