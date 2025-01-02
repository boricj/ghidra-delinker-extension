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

import static ghidra.app.util.ProgramUtil.getOffsetWithinAddressSet;
import static ghidra.app.util.ProgramUtil.patchBytes;
import static ghidra.app.util.exporter.coff.relocs.CoffRelocationTableBuilder.logUnknownRelocation;

import java.util.List;
import java.util.Map;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.relocobj.Relocation;
import ghidra.program.model.relocobj.RelocationAbsolute;
import ghidra.program.model.relocobj.RelocationRelativePC;
import ghidra.util.DataConverter;
import ghidra.util.LittleEndianDataConverter;
import net.boricj.bft.coff.CoffRelocationTable;
import net.boricj.bft.coff.CoffSection;
import net.boricj.bft.coff.CoffSymbolTable;
import net.boricj.bft.coff.CoffSymbolTable.CoffSymbol;
import net.boricj.bft.coff.constants.CoffMachine;
import net.boricj.bft.coff.constants.CoffRelocationType;
import net.boricj.bft.coff.machines.i386.CoffRelocationType_i386;

public class X86_32_CoffRelocationTableBuilder implements CoffRelocationTableBuilder {
	@Override
	public void build(CoffSymbolTable symtab, CoffSection section, byte[] bytes,
			AddressSetView addressSet, List<Relocation> relocations,
			Map<Relocation, CoffSymbol> relocationsToSymbols, MessageLog log) {
		CoffRelocationTable relTable = section.getRelocations();

		for (Relocation relocation : relocations) {
			CoffSymbol symbol = relocationsToSymbols.get(relocation);

			if (relocation instanceof RelocationAbsolute) {
				process(relTable, bytes, addressSet, (RelocationAbsolute) relocation, symbol, log);
			}
			else if (relocation instanceof RelocationRelativePC) {
				process(relTable, bytes, addressSet, (RelocationRelativePC) relocation, symbol,
					log);
			}
			else {
				logUnknownRelocation(relTable.getSection(), relocation, log);
			}
		}
	}

	private void process(CoffRelocationTable relTable, byte[] bytes,
			AddressSetView addressSet, RelocationAbsolute relocation,
			CoffSymbol symbol, MessageLog log) {
		DataConverter dc = LittleEndianDataConverter.INSTANCE;
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long value = relocation.getAddend();

		CoffRelocationType type;
		if (width == 4 && bitmask == 0xffffffffL) {
			type = CoffRelocationType_i386.IMAGE_REL_I386_DIR32;
		}
		else {
			logUnknownRelocation(relTable.getSection(), relocation, log);
			return;
		}

		patchBytes(bytes, addressSet, dc, relocation, value);
		emit(relTable, addressSet, relocation, type, symbol);
	}

	private void process(CoffRelocationTable relTable, byte[] bytes,
			AddressSetView addressSet, RelocationRelativePC relocation,
			CoffSymbol symbol, MessageLog log) {
		DataConverter dc = LittleEndianDataConverter.INSTANCE;
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long value = relocation.getAddend() + width;

		CoffRelocationType type;
		if (width == 4 && bitmask == 0xffffffffL) {
			type = CoffRelocationType_i386.IMAGE_REL_I386_REL32;
		}
		else {
			logUnknownRelocation(relTable.getSection(), relocation, log);
			return;
		}

		patchBytes(bytes, addressSet, dc, relocation, value);
		emit(relTable, addressSet, relocation, type, symbol);
	}

	private void emit(CoffRelocationTable relTable, AddressSetView addressSetView,
			Relocation relocation, CoffRelocationType type, CoffSymbol symbol) {
		int offset = (int) getOffsetWithinAddressSet(addressSetView, relocation.getAddress());

		relTable.add(offset, symbol, type);
	}

	@Override
	public boolean canBuild(CoffMachine machine) {
		return machine == CoffMachine.IMAGE_FILE_MACHINE_I386;
	}
}
