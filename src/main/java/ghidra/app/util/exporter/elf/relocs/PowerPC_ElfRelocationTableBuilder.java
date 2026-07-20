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
import ghidra.program.model.relocobj.RelocationExpressionKind;
import ghidra.program.model.relocobj.RelocationEntry;
import ghidra.program.model.relocobj.RelocationGang;
import ghidra.program.model.relocobj.RelocationGroup;
import ghidra.util.DataConverter;
import net.boricj.bft.elf.ElfFile;
import net.boricj.bft.elf.ElfHeader;
import net.boricj.bft.elf.ElfSection;
import net.boricj.bft.elf.constants.ElfData;
import net.boricj.bft.elf.constants.ElfMachine;
import net.boricj.bft.elf.constants.ElfRelocationType;
import net.boricj.bft.elf.constants.ElfSectionNames;
import net.boricj.bft.elf.constants.ElfSectionType;
import net.boricj.bft.elf.machines.ppc.ElfRelocationType_ppc;
import net.boricj.bft.elf.machines.ppc.ElfRelocationType_ppc64;
import net.boricj.bft.elf.sections.ElfRelaTable;
import net.boricj.bft.elf.sections.ElfSymbolTable;
import net.boricj.bft.elf.sections.ElfSymbolTable.ElfSymbol;

public class PowerPC_ElfRelocationTableBuilder implements ElfRelocationTableBuilder {
	private static final class LoweringResult {
		private final ElfRelocationType type;

		private LoweringResult(ElfRelocationType type) {
			this.type = type;
		}
	}

	public boolean supportsGroupedRelocations() {
		return true;
	}

	@Override
	public ElfSection buildGroups(ElfFile elf, ElfSymbolTable symtab, ElfSection section,
			byte[] bytes, AddressSetView addressSetView, List<RelocationGroup> groups,
			Map<RelocationGroup, ElfSymbol> groupsToSymbols, MessageLog log) {
		String relName = generateSectionName(section, ElfSectionNames._RELA);
		ElfRelaTable relTable = new ElfRelaTable(elf, relName, symtab, section);

		for (RelocationGroup group : groups) {
			ElfSymbol symbol = groupsToSymbols.get(group);
			for (int gangIndex = 0; gangIndex < group.getGangs().size(); gangIndex++) {
				RelocationGang gang = group.getGangs().get(gangIndex);
				for (RelocationEntry entry : gang.getEntries()) {
					process(relTable, bytes, addressSetView, group, gang, gangIndex, entry,
						symbol, log);
				}
			}
		}

		return relTable;
	}

	private static boolean isPpc32(ElfRelaTable relTable) {
		return relTable.getElfFile().getHeader().getMachine() == ElfMachine.EM_PPC;
	}

	private static boolean isPpc64(ElfRelaTable relTable) {
		return relTable.getElfFile().getHeader().getMachine() == ElfMachine.EM_PPC64;
	}

	private void process(ElfRelaTable relTable, byte[] bytes, AddressSetView addressSetView,
			RelocationGroup group, RelocationGang gang, int gangIndex, RelocationEntry entry,
			ElfSymbol symbol, MessageLog log) {
		DataConverter dc = DataConverter.getInstance(
			relTable.getElfFile().getHeader().getIdentData() == ElfData.ELFDATA2MSB);
		int width = gang.getWidth();
		long bitmask = gang.getBitmask();
		long addend = group.getAddend() + entry.localAddend();

		LoweringResult lowering = tryLower(relTable, group, gang, gangIndex);
		if (lowering.type == null) {
			logUnknownRelocation(relTable, group, gang, entry, log);
			return;
		}

		patchBytes(bytes, addressSetView, entry.address(), dc, width, bitmask, 0);
		emit(relTable, addressSetView, entry.address(), lowering.type, symbol, addend);
	}

	private static LoweringResult tryLower(ElfRelaTable relTable, RelocationGroup group,
			RelocationGang gang, int gangIndex) {
		ElfHeader header = relTable.getElfFile().getHeader();
		int width = gang.getWidth();
		long bitmask = gang.getBitmask();
		RelocationExpressionKind kind = group.getExpression().getKind();

		if (kind == RelocationExpressionKind.ABSOLUTE && isPairShape(group, gang)) {
			if (header.getMachine() == ElfMachine.EM_PPC && gangIndex == 0 && width == 4 &&
				bitmask == 0xffffL) {
				return new LoweringResult(ElfRelocationType_ppc.R_PPC_ADDR16_HA);
			}
			if (header.getMachine() == ElfMachine.EM_PPC && gangIndex == 1 && width == 4 &&
				bitmask == 0xffffL) {
				return new LoweringResult(ElfRelocationType_ppc.R_PPC_ADDR16_LO);
			}
			if (header.getMachine() == ElfMachine.EM_PPC64 && gangIndex == 0 && width == 4 &&
				bitmask == 0xffffL) {
				return new LoweringResult(ElfRelocationType_ppc64.R_PPC64_ADDR16_HA);
			}
			if (header.getMachine() == ElfMachine.EM_PPC64 && gangIndex == 1 && width == 4 &&
				bitmask == 0xffffL) {
				return new LoweringResult(ElfRelocationType_ppc64.R_PPC64_ADDR16_LO);
			}
		}

		if (kind == RelocationExpressionKind.PC_RELATIVE) {
			if (header.getMachine() == ElfMachine.EM_PPC && width == 4 && bitmask == 0x03fffffcL) {
				return new LoweringResult(ElfRelocationType_ppc.R_PPC_REL24);
			}
			if (header.getMachine() == ElfMachine.EM_PPC && width == 4 && bitmask == 0x0000fffcL) {
				return new LoweringResult(ElfRelocationType_ppc.R_PPC_REL14);
			}
			if (header.getMachine() == ElfMachine.EM_PPC64 && width == 4 &&
				bitmask == 0x03fffffcL) {
				return new LoweringResult(ElfRelocationType_ppc64.R_PPC64_REL24);
			}
			if (header.getMachine() == ElfMachine.EM_PPC64 && width == 4 &&
				bitmask == 0x0000fffcL) {
				return new LoweringResult(ElfRelocationType_ppc64.R_PPC64_REL14);
			}
		}
		else if (kind == RelocationExpressionKind.ABSOLUTE) {
			if (header.getMachine() == ElfMachine.EM_PPC && width == 4 &&
				bitmask == 0xffffffffL) {
				return new LoweringResult(ElfRelocationType_ppc.R_PPC_ADDR32);
			}
			if (header.getMachine() == ElfMachine.EM_PPC64 && width == 4 &&
				bitmask == 0xffffffffL) {
				return new LoweringResult(ElfRelocationType_ppc64.R_PPC64_ADDR32);
			}
			if (header.getMachine() == ElfMachine.EM_PPC64 && width == 8 &&
				bitmask == 0xffffffffffffffffL) {
				return new LoweringResult(ElfRelocationType_ppc64.R_PPC64_ADDR64);
			}
		}

		return new LoweringResult(null);
	}

	private static boolean isPairShape(RelocationGroup group, RelocationGang gang) {
		return group.getGangs().size() == 2 && gang.getWidth() == 4 && gang.getBitmask() == 0xffffL;
	}

	private void emit(ElfRelaTable relTable, AddressSetView addressSetView,
			ghidra.program.model.address.Address address, ElfRelocationType type, ElfSymbol symbol,
			long addend) {
		long offset = getOffsetWithinAddressSet(addressSetView, address);
		relTable.add(offset, symbol, type, addend);
	}

	@Override
	public boolean canBuild(ElfFile elf, ElfSectionType sectionType) {
		ElfHeader header = elf.getHeader();
		return (header.getMachine() == ElfMachine.EM_PPC ||
			header.getMachine() == ElfMachine.EM_PPC64) &&
			sectionType == ElfSectionType.SHT_RELA;
	}
}