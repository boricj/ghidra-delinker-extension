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
import ghidra.app.util.bin.format.elf.relocation.X86_32_ElfRelocationType;
import ghidra.app.util.exporter.elf.ElfRelocatableObject;
import ghidra.app.util.exporter.elf.ElfRelocatableSection;
import ghidra.app.util.exporter.elf.ElfRelocatableSectionRelTable;
import ghidra.app.util.exporter.elf.ElfRelocatableSectionSymbolTable;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.relocobj.Relocation;
import ghidra.program.model.relocobj.RelocationAbsolute;
import ghidra.program.model.relocobj.RelocationRelativePC;

public class X86_32_RelocationTypeMapper implements ElfRelocationTypeMapper {
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
			else if (relocation instanceof RelocationRelativePC) {
				process(relTable, (RelocationRelativePC) relocation, log);
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
		int width = relocation.getWidth();
		if (width != 4) {
			String msg = String.format("Unknown RelocationAbsolute width %d at %s", width,
				relocation.getAddress());
			log.appendMsg(relTable.getName(), msg);
			return;
		}

		emit(relTable, relocation, X86_32_ElfRelocationType.R_386_32.typeId());
	}

	private void process(ElfRelocatableSectionRelTable relTable, RelocationRelativePC relocation,
			MessageLog log) {
		int width = relocation.getWidth();
		if (width != 4) {
			String msg = String.format("Unknown RelocationRelativePC width %d at %s", width,
				relocation.getAddress());
			log.appendMsg(relTable.getName(), msg);
			return;
		}

		emit(relTable, relocation, X86_32_ElfRelocationType.R_386_PC32.typeId());
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
		return object.getElfMachine() == ElfConstants.EM_386 &&
			object.getElfClass() == ElfConstants.ELF_CLASS_32;
	}
}
