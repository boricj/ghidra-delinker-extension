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
package ghidra.program.model.relocobj;

import static org.junit.Assert.assertArrayEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.DataConverter;

public class RelocationLowPairTest {
	AddressSpace ram = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
	AddressSpace[] spaces = new AddressSpace[] {
		ram,
	};
	AddressFactory addressFactory = null;

	@Before
	public void setUp() {
		addressFactory = new DefaultAddressFactory(spaces);
	}

	@Test
	public void testHI16_LO16_BigEndian_ZeroAddend() {
		Program program = mock(Program.class);
		when(program.getAddressFactory()).thenReturn(addressFactory);

		RelocationTable relocationTable = new RelocationTable(program);
		RelocationHighPair relocationHi =
			new RelocationHighPair(relocationTable, ram.getAddress(4), 4, 0x0000FFFFL, null);
		RelocationLowPair relocationLo = new RelocationLowPair(relocationTable, ram.getAddress(8),
			4, 0x0000FFFFL, relocationHi, 0);
		byte[] buffer = new byte[] { 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
			0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f };
		byte[] expected = new byte[] { 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x00, 0x00, 0x78, 0x79,
			0x00, 0x00, 0x7c, 0x7d, 0x7e, 0x7f };
		relocationLo.unapply(buffer,
			addressFactory.getAddressSet(ram.getAddress(0), ram.getAddress(15)),
			DataConverter.getInstance(true), false);
		assertArrayEquals(expected, buffer);
	}

	@Test
	public void testHI16_LO16_LittleEndian_ZeroAddend() {
		Program program = mock(Program.class);
		when(program.getAddressFactory()).thenReturn(addressFactory);

		RelocationTable relocationTable = new RelocationTable(program);
		RelocationHighPair relocationHi =
			new RelocationHighPair(relocationTable, ram.getAddress(4), 4, 0x0000FFFFL, null);
		RelocationLowPair relocationLo = new RelocationLowPair(relocationTable, ram.getAddress(8),
			4, 0x0000FFFFL, relocationHi, 0);
		byte[] buffer = new byte[] { 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
			0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f };
		byte[] expected = new byte[] { 0x70, 0x71, 0x72, 0x73, 0x00, 0x00, 0x76, 0x77, 0x00, 0x00,
			0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f };
		relocationLo.unapply(buffer,
			addressFactory.getAddressSet(ram.getAddress(0), ram.getAddress(15)),
			DataConverter.getInstance(false), false);
		assertArrayEquals(expected, buffer);
	}

	@Test
	public void testHI16_LO16_LittleEndian_SmallAddend_WithoutEncode() {
		Program program = mock(Program.class);
		when(program.getAddressFactory()).thenReturn(addressFactory);

		RelocationTable relocationTable = new RelocationTable(program);
		RelocationHighPair relocationHi =
			new RelocationHighPair(relocationTable, ram.getAddress(4), 4, 0x0000FFFFL, null);
		RelocationLowPair relocationLo = new RelocationLowPair(relocationTable, ram.getAddress(8),
			4, 0x0000FFFFL, relocationHi, 32766);
		byte[] buffer = new byte[] { 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
			0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f };
		byte[] expected = new byte[] { 0x70, 0x71, 0x72, 0x73, 0x00, 0x00, 0x76, 0x77, 0x00, 0x00,
			0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f };
		relocationLo.unapply(buffer,
			addressFactory.getAddressSet(ram.getAddress(0), ram.getAddress(15)),
			DataConverter.getInstance(false), false);
		assertArrayEquals(expected, buffer);
	}

	@Test
	public void testHI16_LO16_LittleEndian_SmallAddend_WithEncode() {
		Program program = mock(Program.class);
		when(program.getAddressFactory()).thenReturn(addressFactory);

		RelocationTable relocationTable = new RelocationTable(program);
		RelocationHighPair relocationHi =
			new RelocationHighPair(relocationTable, ram.getAddress(4), 4, 0x0000FFFFL, null);
		RelocationLowPair relocationLo = new RelocationLowPair(relocationTable, ram.getAddress(8),
			4, 0x0000FFFFL, relocationHi, 32766);
		byte[] buffer = new byte[] { 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
			0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f };
		byte[] expected = new byte[] { 0x70, 0x71, 0x72, 0x73, 0x00, 0x00, 0x76, 0x77, -2, 0x7f,
			0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f };
		relocationLo.unapply(buffer,
			addressFactory.getAddressSet(ram.getAddress(0), ram.getAddress(15)),
			DataConverter.getInstance(false), true);
		assertArrayEquals(expected, buffer);
	}
}
