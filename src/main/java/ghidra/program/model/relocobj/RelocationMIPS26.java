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

import ghidra.program.model.address.Address;

/**
 * Relocation for a MIPS J-type instruction.
 *
 * The J-type instructions for MIPS encode a jump that is relative to the start of the 256 MiB block that the program
 * counter is in (i.e. it takes the upper 4 bits from the current PC and the next 26 bits from the immediate). It's an
 * hybrid between an absolute and relative jump and therefore require its own relocation type for proper modelization.
 */
public class RelocationMIPS26 extends AbstractRelocationBitmask {
	protected RelocationMIPS26(RelocationTable relocationTable, Address address, String symbolName,
			long addend) {
		super(relocationTable, address, 4, 0x3ffffff, symbolName, addend);
	}
}
