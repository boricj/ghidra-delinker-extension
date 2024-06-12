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
package ghidra.app.util.exporter.coff.mapper;

import java.util.List;

import ghidra.app.util.bin.format.coff.CoffMachineType;
import ghidra.app.util.bin.format.coff.relocation.X86_32_CoffRelocationHandler;
import ghidra.app.util.exporter.coff.CoffRelocatableRelocationTable;
import ghidra.app.util.exporter.coff.CoffRelocatableSection;
import ghidra.app.util.exporter.coff.CoffRelocatableSymbolTable;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.relocobj.Relocation;
import ghidra.program.model.relocobj.RelocationAbsolute;
import ghidra.program.model.relocobj.RelocationRelativePC;

public class X86_32_RelocationTypeMapper implements CoffRelocationTypeMapper {
	@Override
	public void process(CoffRelocatableRelocationTable relTable, List<Relocation> relocations,
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
				log.appendMsg(msg);
			}
		}
	}

	private void process(CoffRelocatableRelocationTable relTable, RelocationAbsolute relocation,
			MessageLog log) {
		int width = relocation.getWidth();
		if (width != 4) {
			String msg = String.format("Unknown RelocationAbsolute width %d at %s", width,
				relocation.getAddress());
			log.appendMsg(msg);
			return;
		}

		emit(relTable, relocation, X86_32_CoffRelocationHandler.IMAGE_REL_I386_DIR32);
	}

	private void process(CoffRelocatableRelocationTable relTable, RelocationRelativePC relocation,
			MessageLog log) {
		int width = relocation.getWidth();
		if (width != 4) {
			String msg = String.format("Unknown RelocationRelativePC width %d at %s", width,
				relocation.getAddress());
			log.appendMsg(msg);
			return;
		}

		emit(relTable, relocation, X86_32_CoffRelocationHandler.IMAGE_REL_I386_REL32);
	}

	private void emit(CoffRelocatableRelocationTable relTable, Relocation relocation, short type) {
		CoffRelocatableSection section = relTable.getSection();
		CoffRelocatableSymbolTable symtab = section.getSymbolTable();

		int offset = (int) section.getOffset(relocation.getAddress());
		int symbolIndex = symtab.getSymbolNumber(relocation.getSymbolName());

		relTable.addRelocation(offset, symbolIndex, type);
	}

	@Override
	public boolean canProcess(int machine) {
		return machine == CoffMachineType.IMAGE_FILE_MACHINE_I386;
	}
}
