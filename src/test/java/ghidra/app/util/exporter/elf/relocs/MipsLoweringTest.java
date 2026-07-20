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

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.relocobj.RelocationEntry;
import ghidra.program.model.relocobj.RelocationExpression;
import ghidra.program.model.relocobj.RelocationExpressionBase;
import ghidra.program.model.relocobj.RelocationGang;
import ghidra.program.model.relocobj.RelocationGangRoleDescriptor;
import ghidra.program.model.relocobj.RelocationGroup;
import net.boricj.bft.elf.machines.mips.ElfRelocationType_Mips;

public class MipsLoweringTest {
	private static final Address TARGET = org.mockito.Mockito.mock(Address.class);

	@Test
	public void derivesHighLowAndRegionRelocationsFromGangOrderAndShape() {
		RelocationGroup highLow = group(RelocationExpression.absolute(),
			gang(RelocationGangRoleDescriptor.ABSOLUTE, 4, 0xffffL),
			gang(RelocationGangRoleDescriptor.ABSOLUTE, 4, 0xffffL));
		RelocationGroup region = group(RelocationExpression.absolute(),
			gang(RelocationGangRoleDescriptor.REGION_RELATIVE, 4, 0x3ffffffL));

		assertEquals(ElfRelocationType_Mips.R_MIPS_HI16,
			MipsLowering.tryLower(highLow, highLow.getGangs().get(0), 0));
		assertEquals(ElfRelocationType_Mips.R_MIPS_LO16,
			MipsLowering.tryLower(highLow, highLow.getGangs().get(1), 1));
		assertEquals(ElfRelocationType_Mips.R_MIPS_26,
			MipsLowering.tryLower(region, region.getGangs().get(0), 0));
	}

	@Test
	public void derivesGpRelativeAndPcRelativeRelocations() {
		RelocationGroup gpRelative = group(
			RelocationExpression.qualifiedSymbol(RelocationExpressionBase.GP, "_gp"),
			gang(RelocationGangRoleDescriptor.SYMBOL_RELATIVE, 4, 0xffffL));
		RelocationGroup pcRelative = group(RelocationExpression.pcRelative(),
			gang(RelocationGangRoleDescriptor.PC_RELATIVE, 4, 0xffffL));

		assertEquals(ElfRelocationType_Mips.R_MIPS_GPREL16,
			MipsLowering.tryLower(gpRelative, gpRelative.getGangs().get(0), 0));
		assertEquals(ElfRelocationType_Mips.R_MIPS_PC16,
			MipsLowering.tryLower(pcRelative, pcRelative.getGangs().get(0), 0));
	}

	private static RelocationGroup group(RelocationExpression expression,
			RelocationGang... gangs) {
		return new RelocationGroup(1, expression, TARGET, 0, List.of(gangs));
	}

	private static RelocationGang gang(RelocationGangRoleDescriptor relocationRole, int width,
			long bitmask) {
		return new RelocationGang(width, bitmask,
			List.of(new RelocationEntry(TARGET, 0)));
	}
}