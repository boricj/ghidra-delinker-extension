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
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.DataConverter;

public interface Relocation {
	public RelocationTable getRelocationTable();

	public Address getAddress();

	public String getSymbolName();

	public long getAddend();

	public void delete();

	public void unapply(byte[] buffer, AddressSetView bufferAddressSet, DataConverter dc,
			boolean encodeAddend, boolean adjustRelativeWithTargetSize);

	default public boolean isNeeded(Program program, AddressSetView addressSet) {
		return true;
	}

	public static void checkBitmask(int width, long bitmask, Long addend) {
		long bitcount = Long.bitCount(bitmask);
		long highestOneBit = Long.numberOfTrailingZeros(Long.highestOneBit(bitmask));
		long lowestOneBit = Long.numberOfTrailingZeros(Long.lowestOneBit(bitmask));

		if (bitcount == 0) {
			throw new IllegalArgumentException("bitmask is empty");
		}
		if (bitcount != (1 + highestOneBit - lowestOneBit)) {
			throw new IllegalArgumentException("bitmask isn't contiguous");
		}
		if (highestOneBit > width * 8) {
			throw new IllegalArgumentException("bitmask wider than relocation width");
		}
		if (addend != null) {
			if (addend >= 0 && (addend >> highestOneBit) != 0) {
				throw new IllegalArgumentException("addend must fit inside bitmask");
			}
			else if (addend < 0 && (addend >> highestOneBit) != -1L) {
				throw new IllegalArgumentException("addend must fit inside bitmask");
			}
		}
	}

	public static long getBitmask(int width) {
		if (width > 8) {
			throw new IllegalArgumentException("width must fit within 64 bit value");
		}
		else if (width == 8) {
			return 0xffffffffffffffffL;
		}
		else {
			return (1L << (width * 8)) - 1;
		}
	}
}
