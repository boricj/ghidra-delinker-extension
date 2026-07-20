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

import ghidra.program.model.relocobj.RelocationExpressionKind;
import ghidra.program.model.relocobj.RelocationGang;
import ghidra.program.model.relocobj.RelocationGroup;
import net.boricj.bft.elf.ElfHeader;
import net.boricj.bft.elf.constants.ElfMachine;
import net.boricj.bft.elf.constants.ElfRelocationType;
import net.boricj.bft.elf.machines.ppc.ElfRelocationType_ppc;
import net.boricj.bft.elf.machines.ppc.ElfRelocationType_ppc64;
import net.boricj.bft.elf.sections.ElfRelaTable;

final class PowerPCLowering {
	private PowerPCLowering() {
	}

	static ElfRelocationType tryLower(ElfRelaTable relTable, RelocationGroup group,
			RelocationGang gang, int gangIndex) {
		ElfHeader header = relTable.getElfFile().getHeader();
		int width = gang.getWidth();
		long bitmask = gang.getBitmask();
		RelocationExpressionKind kind = group.getExpression().getKind();

		if (kind == RelocationExpressionKind.ABSOLUTE && isPairShape(group, gang)) {
			if (header.getMachine() == ElfMachine.EM_PPC && gangIndex == 0 && width == 4 &&
				bitmask == 0xffffL) {
				return ElfRelocationType_ppc.R_PPC_ADDR16_HA;
			}
			if (header.getMachine() == ElfMachine.EM_PPC && gangIndex == 1 && width == 4 &&
				bitmask == 0xffffL) {
				return ElfRelocationType_ppc.R_PPC_ADDR16_LO;
			}
			if (header.getMachine() == ElfMachine.EM_PPC64 && gangIndex == 0 && width == 4 &&
				bitmask == 0xffffL) {
				return ElfRelocationType_ppc64.R_PPC64_ADDR16_HA;
			}
			if (header.getMachine() == ElfMachine.EM_PPC64 && gangIndex == 1 && width == 4 &&
				bitmask == 0xffffL) {
				return ElfRelocationType_ppc64.R_PPC64_ADDR16_LO;
			}
		}

		if (kind == RelocationExpressionKind.PC_RELATIVE) {
			if (header.getMachine() == ElfMachine.EM_PPC && width == 4 && bitmask == 0x03fffffcL) {
				return ElfRelocationType_ppc.R_PPC_REL24;
			}
			if (header.getMachine() == ElfMachine.EM_PPC && width == 4 && bitmask == 0x0000fffcL) {
				return ElfRelocationType_ppc.R_PPC_REL14;
			}
			if (header.getMachine() == ElfMachine.EM_PPC64 && width == 4 && bitmask == 0x03fffffcL) {
				return ElfRelocationType_ppc64.R_PPC64_REL24;
			}
			if (header.getMachine() == ElfMachine.EM_PPC64 && width == 4 && bitmask == 0x0000fffcL) {
				return ElfRelocationType_ppc64.R_PPC64_REL14;
			}
		}
		else if (kind == RelocationExpressionKind.ABSOLUTE) {
			if (header.getMachine() == ElfMachine.EM_PPC && width == 4 &&
				bitmask == 0xffffffffL) {
				return ElfRelocationType_ppc.R_PPC_ADDR32;
			}
			if (header.getMachine() == ElfMachine.EM_PPC64 && width == 4 &&
				bitmask == 0xffffffffL) {
				return ElfRelocationType_ppc64.R_PPC64_ADDR32;
			}
			if (header.getMachine() == ElfMachine.EM_PPC64 && width == 8 &&
				bitmask == 0xffffffffffffffffL) {
				return ElfRelocationType_ppc64.R_PPC64_ADDR64;
			}
		}

		return null;
	}

	private static boolean isPairShape(RelocationGroup group, RelocationGang gang) {
		return group.getGangs().size() == 2 && gang.getWidth() == 4 &&
			gang.getBitmask() == 0xffffL;
	}
}