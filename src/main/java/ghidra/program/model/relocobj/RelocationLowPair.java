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

public class RelocationLowPair implements Relocation {
	private final RelocationTable relocationTable;
	private final Address address;
	private final int width;
	private final long bitmask;
	private final long addend;
	private final RelocationHighPair relocationHi;

	protected RelocationLowPair(RelocationTable relocationTable, Address address, int width,
			long bitmask, RelocationHighPair relocationHi, long addend) {
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
	public int getWidth() {
		return width;
	}

	@Override
	public long getBitmask() {
		return bitmask;
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
