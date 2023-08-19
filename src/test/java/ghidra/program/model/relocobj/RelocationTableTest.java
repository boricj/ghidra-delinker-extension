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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.DataConverter;

public class RelocationTableTest {
	AddressSpace ram = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
	AddressSpace[] spaces = new AddressSpace[] {
		ram,
	};
	AddressFactory addressFactory = null;
	MemoryBlock memoryBlock = null;
	Memory memory = null;
	Program program = null;

	@Before
	public void setUp() throws MemoryAccessException {
		addressFactory = new DefaultAddressFactory(spaces);

		memoryBlock = mock(MemoryBlock.class);
		when(memoryBlock.getBytes(any(Address.class), any(byte[].class), anyInt(), anyInt()))
				.thenAnswer(
					new Answer<Integer>() {
						public Integer answer(InvocationOnMock invocation) {
							Object[] args = invocation.getArguments();

							Address address = (Address) args[0];
							byte[] buffer = (byte[]) args[1];
							int offset = (int) args[2];
							int length = (int) args[3];

							for (int i = 0; i < length; i++) {
								buffer[offset + i] = (byte) (address.getOffset() + i + 1);
							}
							return length;
						}
					});
		doReturn(true).when(memoryBlock).isInitialized();
		doReturn(ram.getAddress(0)).when(memoryBlock).getStart();
		doReturn(ram.getAddress(31)).when(memoryBlock).getEnd();

		memory = mock(Memory.class);
		when(memory.getBlock(any(Address.class))).thenReturn(memoryBlock);

		program = mock(Program.class);
		when(program.getAddressFactory()).thenReturn(addressFactory);
		when(program.getMemory()).thenReturn(memory);
	}

	@Test
	public void testGetOriginalBytes_FullView() throws MemoryAccessException {
		RelocationTable relocationTable = new RelocationTable(program);
		AddressSetView addressSet =
			addressFactory.getAddressSet(ram.getAddress(0), ram.getAddress(15));
		byte[] output =
			relocationTable.getOriginalBytes(addressSet, DataConverter.getInstance(false), false);
		byte[] expected = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
			0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
		assertArrayEquals(expected, output);
	}

	@Test
	public void testGetOriginalBytes_Hole() throws MemoryAccessException {
		RelocationTable relocationTable = new RelocationTable(program);
		AddressSetView addressSet =
			addressFactory.getAddressSet(ram.getAddress(0), ram.getAddress(15));
		addressSet = addressSet
				.subtract(addressFactory.getAddressSet(ram.getAddress(4), ram.getAddress(11)));
		byte[] output =
			relocationTable.getOriginalBytes(addressSet, DataConverter.getInstance(false), false);
		byte[] expected = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x0d, 0x0e, 0x0f, 0x10 };
		assertArrayEquals(expected, output);
	}

	@Test
	public void testGetOriginalBytes_Holes() throws MemoryAccessException {
		RelocationTable relocationTable = new RelocationTable(program);
		AddressSetView addressSet =
			addressFactory.getAddressSet(ram.getAddress(0), ram.getAddress(15));
		addressSet =
			addressSet.subtract(addressFactory.getAddressSet(ram.getAddress(0), ram.getAddress(4)));
		addressSet = addressSet
				.subtract(addressFactory.getAddressSet(ram.getAddress(7), ram.getAddress(12)));
		byte[] output =
			relocationTable.getOriginalBytes(addressSet, DataConverter.getInstance(false), false);
		byte[] expected = new byte[] { 0x06, 0x07, 0x0e, 0x0f, 0x10 };
		assertArrayEquals(expected, output);
	}
}
