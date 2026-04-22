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
import ghidra.program.model.relocobj.RelocationHighPair;
import ghidra.program.model.relocobj.RelocationLowPair;
import ghidra.program.model.relocobj.RelocationRelativePC;
import ghidra.util.DataConverter;
import net.boricj.bft.coff.CoffRelocationTable;
import net.boricj.bft.coff.CoffSection;
import net.boricj.bft.coff.CoffSymbolTable;
import net.boricj.bft.coff.CoffSymbolTable.CoffSymbol;
import net.boricj.bft.coff.constants.CoffMachine;
import net.boricj.bft.coff.constants.CoffRelocationType;
import net.boricj.bft.coff.machines.powerpcbe.CoffRelocationType_powerpcbe;

public class PowerPC_32_CoffRelocationTableBuilder implements CoffRelocationTableBuilder {
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
			else if (relocation instanceof RelocationHighPair) {
				RelocationHighPair highPair = (RelocationHighPair) relocation;
				process(relTable, bytes, addressSet, highPair, symbol, log);

				for (RelocationLowPair lowPair : highPair.getLowPairs()) {
					process(relTable, bytes, addressSet, lowPair, symbol, log);
				}
			}
			else if (relocation instanceof RelocationLowPair) {
				// Low pairs are emitted when processing their associated high pair.
				continue;
			}
			else {
				logUnknownRelocation(relTable.getSection(), relocation, log);
			}
		}
	}

	private void process(CoffRelocationTable relTable, byte[] bytes,
			AddressSetView addressSet, RelocationAbsolute relocation,
			CoffSymbol symbol, MessageLog log) {
		DataConverter dc = DataConverter.getInstance(true);
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long value = relocation.getAddend();

		CoffRelocationType type;
		if (width == 4 && bitmask == 0xffffffffL) {
			type = CoffRelocationType_powerpcbe.IMAGE_REL_PPC_ADDR32;
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
		DataConverter dc = DataConverter.getInstance(true);
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long offset = getOffsetWithinAddressSet(addressSet, relocation.getAddress());
		long value = (relocation.getAddend() - offset) >> 2;

		CoffRelocationType type;
		if (width == 4 && bitmask == 0x03fffffcL) {
			type = CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REL24;
		}
		else if (width == 4 && bitmask == 0x0000fffcL) {
			type = CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REL14;
		}
		else {
			logUnknownRelocation(relTable.getSection(), relocation, log);
			return;
		}

		patchBytes(bytes, addressSet, dc, relocation, value);
		emit(relTable, addressSet, relocation, type, symbol);
	}

	private void process(CoffRelocationTable relTable, byte[] bytes,
			AddressSetView addressSet, RelocationHighPair relocation, CoffSymbol symbol,
			MessageLog log) {
		DataConverter dc = DataConverter.getInstance(true);
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long value = relocation.getAddend();

		CoffRelocationType type;
		if (width == 4 && bitmask == 0xffffL) {
			type = CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REFHI;
		}
		else {
			logUnknownRelocation(relTable.getSection(), relocation, log);
			return;
		}

		patchBytes(bytes, addressSet, dc, relocation, value);
		emit(relTable, addressSet, relocation, type, symbol);
		emitPair(relTable, addressSet, relocation);
	}

	private void process(CoffRelocationTable relTable, byte[] bytes,
			AddressSetView addressSet, RelocationLowPair relocation, CoffSymbol symbol,
			MessageLog log) {
		DataConverter dc = DataConverter.getInstance(true);
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long value = relocation.getAddend();

		CoffRelocationType type;
		if (width == 4 && bitmask == 0xffffL) {
			type = CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REFLO;
		}
		else {
			logUnknownRelocation(relTable.getSection(), relocation, log);
			return;
		}

		patchBytes(bytes, addressSet, dc, relocation, value);
		emit(relTable, addressSet, relocation, type, symbol);
		emitPair(relTable, addressSet, relocation);
	}

	private void emit(CoffRelocationTable relTable, AddressSetView addressSetView,
			Relocation relocation, CoffRelocationType type, CoffSymbol symbol) {
		int offset = (int) getOffsetWithinAddressSet(addressSetView, relocation.getAddress());
		relTable.add(offset, symbol, type);
	}

	private void emitPair(CoffRelocationTable relTable, AddressSetView addressSetView,
			Relocation relocation) {
		int offset = (int) getOffsetWithinAddressSet(addressSetView, relocation.getAddress());
		relTable.add(offset, 0, CoffRelocationType_powerpcbe.IMAGE_REL_PPC_PAIR);
	}

	@Override
	public boolean canBuild(CoffMachine machine) {
		return machine == CoffMachine.IMAGE_FILE_MACHINE_POWERPCBE;
	}
}
