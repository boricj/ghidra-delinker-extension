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

import static ghidra.app.util.ProgramUtil.patchBytes;
import static ghidra.app.util.exporter.coff.relocs.CoffRelocationTableBuilder.logUnknownRelocation;

import java.util.List;

import ghidra.app.util.bin.format.coff.CoffMachineType;
import ghidra.app.util.bin.format.coff.relocation.X86_32_CoffRelocationHandler;
import ghidra.app.util.exporter.coff.CoffRelocatableRelocationTable;
import ghidra.app.util.exporter.coff.CoffRelocatableSection;
import ghidra.app.util.exporter.coff.CoffRelocatableSymbolTable;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.relocobj.Relocation;
import ghidra.program.model.relocobj.RelocationAbsolute;
import ghidra.program.model.relocobj.RelocationRelativePC;
import ghidra.util.DataConverter;
import ghidra.util.LittleEndianDataConverter;

public class X86_32_CoffRelocationTableBuilder implements CoffRelocationTableBuilder {
	@Override
	public void build(CoffRelocatableSymbolTable symtab, CoffRelocatableSection section,
			byte[] bytes, AddressSetView addressSet, List<Relocation> relocations, MessageLog log) {
		CoffRelocatableRelocationTable relTable = section.getRelocationTable();

		for (Relocation relocation : relocations) {
			if (relocation instanceof RelocationAbsolute) {
				process(relTable, bytes, addressSet, (RelocationAbsolute) relocation, log);
			}
			else if (relocation instanceof RelocationRelativePC) {
				process(relTable, bytes, addressSet, (RelocationRelativePC) relocation, log);
			}
			else {
				logUnknownRelocation(relTable.getSection(), relocation, log);
			}
		}
	}

	private void process(CoffRelocatableRelocationTable relTable, byte[] bytes,
			AddressSetView addressSet, RelocationAbsolute relocation,
			MessageLog log) {
		DataConverter dc = LittleEndianDataConverter.INSTANCE;
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long value = relocation.getAddend();

		short type;
		if (width == 4 && bitmask == 0xffffffffL) {
			type = X86_32_CoffRelocationHandler.IMAGE_REL_I386_DIR32;
		}
		else {
			logUnknownRelocation(relTable.getSection(), relocation, log);
			return;
		}

		patchBytes(bytes, addressSet, dc, relocation, value);
		emit(relTable, relocation, type);
	}

	private void process(CoffRelocatableRelocationTable relTable, byte[] bytes,
			AddressSetView addressSet, RelocationRelativePC relocation,
			MessageLog log) {
		DataConverter dc = LittleEndianDataConverter.INSTANCE;
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long value = relocation.getAddend() + width;

		short type;
		if (width == 4 && bitmask == 0xffffffffL) {
			type = X86_32_CoffRelocationHandler.IMAGE_REL_I386_REL32;
		}
		else {
			logUnknownRelocation(relTable.getSection(), relocation, log);
			return;
		}

		patchBytes(bytes, addressSet, dc, relocation, value);
		emit(relTable, relocation, type);
	}

	private void emit(CoffRelocatableRelocationTable relTable, Relocation relocation, short type) {
		CoffRelocatableSection section = relTable.getSection();
		CoffRelocatableSymbolTable symtab = section.getSymbolTable();

		int offset = (int) section.getOffset(relocation.getAddress());
		int symbolIndex = symtab.getSymbolNumber(relocation.getSymbolName());

		relTable.addRelocation(offset, symbolIndex, type);
	}

	@Override
	public boolean canBuild(short machine) {
		return machine == CoffMachineType.IMAGE_FILE_MACHINE_I386;
	}
}
