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

import ghidra.program.model.relocobj.RelocationExpressionKind;
import ghidra.program.model.relocobj.RelocationGang;
import ghidra.program.model.relocobj.RelocationGroup;
import net.boricj.bft.coff.constants.CoffRelocationType;
import net.boricj.bft.coff.machines.ppc.CoffRelocationType_ppc;

final class PowerPCRelocationTableLowering {
	static final class Result {
		private final CoffRelocationType type;
		private final long value;
		private final boolean emitPair;

		private Result(CoffRelocationType type, long value, boolean emitPair) {
			this.type = type;
			this.value = value;
			this.emitPair = emitPair;
		}

		CoffRelocationType type() {
			return type;
		}

		long value() {
			return value;
		}

		boolean emitPair() {
			return emitPair;
		}
	}

	private PowerPCRelocationTableLowering() {
	}

	static Result tryLower(RelocationGroup group, RelocationGang gang, int gangIndex,
			long addend, long offset) {
		int width = gang.getWidth();
		long bitmask = gang.getBitmask();
		RelocationExpressionKind kind = group.getExpression().getKind();

		if (kind == RelocationExpressionKind.ABSOLUTE && isPairShape(group, gang)) {
			if (gangIndex == 0) {
				return new Result(CoffRelocationType_ppc.IMAGE_REL_PPC_REFHI, addend, true);
			}
			if (gangIndex == 1) {
				return new Result(CoffRelocationType_ppc.IMAGE_REL_PPC_REFLO, addend, true);
			}
		}

		if (kind == RelocationExpressionKind.PC_RELATIVE) {
			if (width == 4 && bitmask == 0x03fffffcL) {
				return new Result(CoffRelocationType_ppc.IMAGE_REL_PPC_REL24,
					(addend - offset) >> 2, false);
			}
			if (width == 4 && bitmask == 0x0000fffcL) {
				return new Result(CoffRelocationType_ppc.IMAGE_REL_PPC_REL14,
					(addend - offset) >> 2, false);
			}
		}
		else if (kind == RelocationExpressionKind.ABSOLUTE) {
			if (width == 4 && bitmask == 0xffffffffL) {
				return new Result(CoffRelocationType_ppc.IMAGE_REL_PPC_ADDR32, addend, false);
			}
		}

		return null;
	}

	private static boolean isPairShape(RelocationGroup group, RelocationGang gang) {
		return group.getGangs().size() == 2 && gang.getWidth() == 4 &&
			gang.getBitmask() == 0xffffL;
	}
}