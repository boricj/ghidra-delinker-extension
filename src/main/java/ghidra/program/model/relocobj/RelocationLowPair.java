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
import ghidra.util.DataConverter;

public class RelocationLowPair implements Relocation {
	private final RelocationTable relocationTable;
	private final Address address;
	private final int width;
	private final long bitmask;
	private final long addend;
	private final RelocationHighPair relocationHi;

	protected RelocationLowPair(RelocationTable relocationTable, Address address, int width,
			long bitmask, RelocationHighPair relocationHi, long addend) {
		// FIXME: Support large addends with carry and stuff.
		Relocation.checkBitmask(width, bitmask, 0, addend);

		this.relocationTable = relocationTable;
		this.address = address;
		this.width = width;
		this.bitmask = bitmask;
		this.addend = addend;
		this.relocationHi = relocationHi;

		relocationHi.addRelocationLo(this);
	}

	@Override
	public RelocationTable getRelocationTable() {
		return relocationTable;
	}

	@Override
	public Address getAddress() {
		return address;
	}

	@Override
	public String getSymbolName() {
		return relocationHi.getSymbolName();
	}

	@Override
	public long getAddend() {
		return addend;
	}

	@Override
	public void delete() {
		relocationHi.removeRelocationLo(this);
		relocationTable.delete(this);
	}

	@Override
	public void unapply(byte[] buffer, AddressSetView addressSet, DataConverter dc,
			boolean encodeAddend) {
		// Low relocation.
		if (!addressSet.contains(address, address.add(width - 1))) {
			throw new IllegalArgumentException("buffer does not contain low pair relocation");
		}

		int offset = (int) Relocation.getAddressOffsetWithinSet(addressSet, address);
		long value = dc.getValue(buffer, offset, width) & ~bitmask;
		if (encodeAddend) {
			value = value | (addend << Long.numberOfTrailingZeros(Long.lowestOneBit(bitmask)));
		}
		dc.putValue(value, width, buffer, offset);

		// High relocation.
		relocationHi.unapplyHi(buffer, addressSet, dc);
	}

	public int getWidth() {
		return width;
	}

	public long getBitmask() {
		return bitmask;
	}

	public Relocation getRelocationHi() {
		return relocationHi;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof RelocationLowPair)) {
			return false;
		}

		RelocationLowPair rel = (RelocationLowPair) obj;
		return address.equals(rel.getAddress()) && width == rel.getWidth() &&
			bitmask == rel.getBitmask() && addend == rel.getAddend();
	}
}
