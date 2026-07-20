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

import ghidra.program.model.relocobj.RelocationExpressionBase;
import ghidra.program.model.relocobj.RelocationExpressionKind;
import ghidra.program.model.relocobj.RelocationGang;
import ghidra.program.model.relocobj.RelocationGroup;
import net.boricj.bft.elf.constants.ElfRelocationType;
import net.boricj.bft.elf.machines.mips.ElfRelocationType_Mips;
import net.boricj.bft.elf.sections.ElfRelTable;

final class MipsLowering {
	private MipsLowering() {
	}

	static ElfRelocationType tryLower(RelocationGroup group, RelocationGang gang,
			int gangIndex) {
		int width = gang.getWidth();
		long bitmask = gang.getBitmask();
		RelocationExpressionKind kind = group.getExpression().getKind();
		RelocationExpressionBase base = group.getExpression().getBase();

		if (kind == RelocationExpressionKind.SYMBOL_RELATIVE && base == RelocationExpressionBase.GP) {
			if (width == 4 && bitmask == 0xffff) {
				return ElfRelocationType_Mips.R_MIPS_GPREL16;
			}
		}

		if (kind == RelocationExpressionKind.PC_RELATIVE) {
			if (width == 4 && bitmask == 0xffff) {
				return ElfRelocationType_Mips.R_MIPS_PC16;
			}
		}

		if (kind == RelocationExpressionKind.ABSOLUTE) {
			if (isPairShape(group, gang)) {
				if (gangIndex == 0) {
					return ElfRelocationType_Mips.R_MIPS_HI16;
				}
				if (gangIndex == 1) {
					return ElfRelocationType_Mips.R_MIPS_LO16;
				}
			}
			if (width == 4 && bitmask == 0x3ffffff) {
				return ElfRelocationType_Mips.R_MIPS_26;
			}
			if (width == 4 && bitmask == 0xffffffffL) {
				return ElfRelocationType_Mips.R_MIPS_32;
			}
			if (width == 8 && bitmask == 0xffffffffffffffffL) {
				return ElfRelocationType_Mips.R_MIPS_64;
			}
		}

		return null;
	}

	private static boolean isPairShape(RelocationGroup group, RelocationGang gang) {
		return group.getGangs().size() == 2 && gang.getWidth() == 4 && gang.getBitmask() == 0xffffL;
	}
}