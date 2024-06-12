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
package ghidra.app.util.exporter.elf.mapper;

import java.util.List;

import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.relocation.MIPS_ElfRelocationType;
import ghidra.app.util.exporter.elf.ElfRelocatableObject;
import ghidra.app.util.exporter.elf.ElfRelocatableSection;
import ghidra.app.util.exporter.elf.ElfRelocatableSectionRelTable;
import ghidra.app.util.exporter.elf.ElfRelocatableSectionSymbolTable;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.relocobj.Relocation;
import ghidra.program.model.relocobj.RelocationAbsolute;
import ghidra.program.model.relocobj.RelocationHighPair;
import ghidra.program.model.relocobj.RelocationLowPair;
import ghidra.program.model.relocobj.RelocationMIPS26;
import ghidra.program.model.relocobj.RelocationRelativePC;
import ghidra.program.model.relocobj.RelocationRelativeSymbol;

public class Mips_RelocationTypeMapper implements ElfRelocationTypeMapper {
	@Override
	public void process(ElfRelocatableSection table, List<Relocation> relocations, MessageLog log) {
		if (table instanceof ElfRelocatableSectionRelTable) {
			process((ElfRelocatableSectionRelTable) table, relocations, log);
		}
		else {
			String msg = String.format("Unexpected relocation table type %s, table not filled",
				table.getClass().getSimpleName());
			log.appendMsg(getClass().getSimpleName(), msg);
		}
	}

	private void process(ElfRelocatableSectionRelTable relTable, List<Relocation> relocations,
			MessageLog log) {
		for (Relocation relocation : relocations) {
			if (relocation instanceof RelocationAbsolute) {
				process(relTable, (RelocationAbsolute) relocation, log);
			}
			else if (relocation instanceof RelocationHighPair) {
				RelocationHighPair highPair = (RelocationHighPair) relocation;
				process(relTable, highPair, log);

				for (RelocationLowPair lowPair : highPair.getLowPairs()) {
					process(relTable, lowPair, log);
				}
			}
			else if (relocation instanceof RelocationLowPair) {
				// Low pairs are processed by their high pair.
				continue;
			}
			else if (relocation instanceof RelocationRelativePC) {
				process(relTable, (RelocationRelativePC) relocation, log);
			}
			else if (relocation instanceof RelocationRelativeSymbol) {
				process(relTable, (RelocationRelativeSymbol) relocation, log);
			}
			else if (relocation instanceof RelocationMIPS26) {
				process(relTable, (RelocationMIPS26) relocation, log);
			}
			else {
				String name = relocation.getClass().getSimpleName();
				String msg = String.format("Unknown relocation type %s at %s", name,
					relocation.getAddress());
				log.appendMsg(relTable.getName(), msg);
			}
		}
	}

	private void process(ElfRelocatableSectionRelTable relTable, RelocationAbsolute relocation,
			MessageLog log) {
		long type;
		int width = relocation.getWidth();
		switch (width) {
			case 4:
				type = MIPS_ElfRelocationType.R_MIPS_32.typeId();
				break;
			case 8:
				type = MIPS_ElfRelocationType.R_MIPS_64.typeId();
				break;
			default:
				String msg = String.format("Unknown RelocationAbsolute width %d at %s", width,
					relocation.getAddress());
				log.appendMsg(relTable.getName(), msg);
				return;
		}

		emit(relTable, relocation, type);
	}

	private void process(ElfRelocatableSectionRelTable relTable, RelocationHighPair relocation,
			MessageLog log) {
		long bitfield = relocation.getBitmask();

		if (bitfield != 0xffff) {
			String msg = String.format("Unknown RelocationHighPair bitfield 0x%x at %s", bitfield,
				relocation.getAddress());
			log.appendMsg(relTable.getName(), msg);
			return;
		}

		emit(relTable, relocation, MIPS_ElfRelocationType.R_MIPS_HI16.typeId());
	}

	private void process(ElfRelocatableSectionRelTable relTable, RelocationLowPair relocation,
			MessageLog log) {
		long bitfield = relocation.getBitmask();

		if (bitfield != 0xffff) {
			String msg = String.format("Unknown RelocationLowPair bitfield 0x%x at %s", bitfield,
				relocation.getAddress());
			log.appendMsg(relTable.getName(), msg);
			return;
		}

		emit(relTable, relocation, MIPS_ElfRelocationType.R_MIPS_LO16.typeId());
	}

	private void process(ElfRelocatableSectionRelTable relTable,
			RelocationRelativeSymbol relocation, MessageLog log) {
		int width = relocation.getWidth();
		long bitfield = relocation.getBitmask();
		String symbol = relocation.getRelativeSymbolName();

		if (width != 2 || bitfield != 0xffff || !symbol.equals("_gp")) {
			String msg = String.format(
				"Unknown RelocationRelativeSymbol width %d bitfield 0x%x symbol %s at %s", width,
				bitfield, symbol, relocation.getAddress());
			log.appendMsg(relTable.getName(), msg);
			return;
		}

		emit(relTable, relocation, MIPS_ElfRelocationType.R_MIPS_GPREL16.typeId());
	}

	private void process(ElfRelocatableSectionRelTable relTable, RelocationRelativePC relocation,
			MessageLog log) {
		int width = relocation.getWidth();
		long bitfield = relocation.getBitmask();

		if (width != 2 || bitfield != 0xffff) {
			String msg = String.format("Unknown RelocationRelativePC width %d bitfield 0x%x at %s",
				width, bitfield, relocation.getAddress());
			log.appendMsg(relTable.getName(), msg);
			return;
		}

		emit(relTable, relocation, MIPS_ElfRelocationType.R_MIPS_PC16.typeId());
	}

	private void process(ElfRelocatableSectionRelTable relTable, RelocationMIPS26 relocation,
			MessageLog log) {
		emit(relTable, relocation, MIPS_ElfRelocationType.R_MIPS_26.typeId());
	}

	private void emit(ElfRelocatableSectionRelTable relTable, Relocation relocation, long type) {
		ElfRelocatableSection section = relTable.getSection();
		ElfRelocatableSectionSymbolTable symtab = relTable.getSymbolTable();

		long offset = section.getOffset(relocation.getAddress());
		long symindex = symtab.indexOf(symtab.get(relocation.getSymbolName()));

		relTable.add(offset, type, symindex);
	}

	@Override
	public boolean canProcess(ElfRelocatableObject object) {
		return object.getElfMachine() == ElfConstants.EM_MIPS;
	}
}
