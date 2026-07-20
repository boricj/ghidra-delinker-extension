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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.relocobj.RelocationEntry;
import ghidra.program.model.relocobj.RelocationExpression;
import ghidra.program.model.relocobj.RelocationGang;
import ghidra.program.model.relocobj.RelocationGangRoleDescriptor;
import ghidra.program.model.relocobj.RelocationGroup;
import net.boricj.bft.coff.machines.ppc.CoffRelocationType_ppc;

public class PowerPCRelocationTableLoweringTest {
	private static final Address TARGET = org.mockito.Mockito.mock(Address.class);

	@Test
	public void derivesHighAndLowPairRelocationsFromGangOrder() {
		RelocationGroup group = group(RelocationExpression.absolute(),
			gang(RelocationGangRoleDescriptor.ABSOLUTE, 4, 0xffffL),
			gang(RelocationGangRoleDescriptor.ABSOLUTE, 4, 0xffffL));

		PowerPCRelocationTableLowering.Result high =
			PowerPCRelocationTableLowering.tryLower(group, group.getGangs().get(0), 0, 0, 0);
		PowerPCRelocationTableLowering.Result low =
			PowerPCRelocationTableLowering.tryLower(group, group.getGangs().get(1), 1, 0, 0);

		assertEquals(CoffRelocationType_ppc.IMAGE_REL_PPC_REFHI, high.type());
		assertEquals(CoffRelocationType_ppc.IMAGE_REL_PPC_REFLO, low.type());
		assertTrue(high.emitPair());
		assertTrue(low.emitPair());
	}

	@Test
	public void derivesPcRelativeAndAbsoluteRelocations() {
		RelocationGroup pcRelative = group(RelocationExpression.pcRelative(),
			gang(RelocationGangRoleDescriptor.PC_RELATIVE, 4, 0x03fffffcL));
		RelocationGroup absolute = group(RelocationExpression.absolute(),
			gang(RelocationGangRoleDescriptor.ABSOLUTE, 4, 0xffffffffL));

		assertEquals(CoffRelocationType_ppc.IMAGE_REL_PPC_REL24,
			PowerPCRelocationTableLowering.tryLower(pcRelative, pcRelative.getGangs().get(0), 0,
				0, 0).type());
		assertEquals(CoffRelocationType_ppc.IMAGE_REL_PPC_ADDR32,
			PowerPCRelocationTableLowering.tryLower(absolute, absolute.getGangs().get(0), 0,
				0, 0).type());
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