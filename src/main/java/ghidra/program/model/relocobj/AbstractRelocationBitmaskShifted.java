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

public abstract class AbstractRelocationBitmaskShifted implements Relocation {
	private final RelocationTable relocationTable;
	private final Address address;
	private final int width;
	private final long bitmask;
	private final int shift;
	private final String symbolName;
	private final long addend;

	protected AbstractRelocationBitmaskShifted(RelocationTable relocationTable, Address address,
			int width, String symbolName, long addend) {
		this(relocationTable, address, width, Relocation.getBitmask(width), 0, symbolName, addend);
	}

	protected AbstractRelocationBitmaskShifted(RelocationTable relocationTable, Address address,
			int width, long bitmask, int shift, String symbolName, long addend) {
		Relocation.checkBitmask(width, bitmask, shift, addend);

		this.relocationTable = relocationTable;
		this.address = address;
		this.width = width;
		this.bitmask = bitmask;
		this.shift = shift;
		this.symbolName = symbolName;
		this.addend = addend;
	}

	@Override
	public RelocationTable getRelocationTable() {
		return relocationTable;
	}

	@Override
	public Address getAddress() {
		return address;
	}

	public int getWidth() {
		return width;
	}

	public long getBitmask() {
		return bitmask;
	}

	public int getShift() {
		return shift;
	}

	@Override
	public String getSymbolName() {
		return symbolName;
	}

	@Override
	public long getAddend() {
		return addend;
	}

	@Override
	public void delete() {
		relocationTable.delete(this);
	}

	@Override
	public void unapply(byte[] buffer, AddressSetView addressSet, DataConverter dc,
			boolean encodeAddend) {
		if (!addressSet.contains(address, address.add(width - 1))) {
			throw new IllegalArgumentException("buffer does not contain relocation");
		}

		int offset = (int) Relocation.getAddressOffsetWithinSet(addressSet, address);
		long value = dc.getValue(buffer, offset, width) & ~bitmask;
		int bitmaskShift = Long.numberOfTrailingZeros(Long.lowestOneBit(bitmask));
		if (encodeAddend) {
			value = value | ((addend >> shift) << bitmaskShift);
		}
		dc.putValue(value, width, buffer, offset);
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof AbstractRelocationBitmaskShifted)) {
			return false;
		}

		AbstractRelocationBitmaskShifted rel = (AbstractRelocationBitmaskShifted) obj;
		return address.equals(rel.getAddress()) && width == rel.getWidth() &&
			bitmask == rel.getBitmask() && shift == rel.getShift() &&
			symbolName.equals(rel.getSymbolName()) && addend == rel.getAddend();
	}
}
