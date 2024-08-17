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
package ghidra.app.util.exporter.coff;

import java.io.DataOutput;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.util.DataConverter;

public class CoffRelocatableRelocationTable {
	public final static int RECORD_SIZE = 10;

	private final CoffRelocatableSection section;
	private final List<Relocation> relocations = new ArrayList<>();
	protected int offset;

	public static final class Relocation {
		int virtualAddress;
		int symbol;
		short type;

		public Relocation(int virtualAddress, int symbol, short type) {
			this.virtualAddress = virtualAddress;
			this.symbol = symbol;
			this.type = type;
		}
	}

	public CoffRelocatableRelocationTable(CoffRelocatableSection section) {
		this.section = section;
	}

	public CoffRelocatableSection getSection() {
		return section;
	}

	public void addRelocation(int offset, int symbol, short type) {
		relocations.add(new Relocation(offset, symbol, type));
	}

	public boolean linkOverflow() {
		return relocations.size() > 65535;
	}

	public short headerCount() {
		if (linkOverflow()) {
			return (short) 65535;
		}
		return (short) relocations.size();
	}

	private int extendedCount() {
		if (linkOverflow()) {
			return relocations.size() + 1;
		}
		return relocations.size();
	}

	public int size() {
		return extendedCount() * RECORD_SIZE;
	}

	public void write(DataOutput out, DataConverter dc) throws IOException {
		byte[] record = new byte[RECORD_SIZE];
		if (linkOverflow()) {
			dc.putInt(record, 0, extendedCount());
			dc.putInt(record, 4, 0);
			dc.putShort(record, 8, (short) 0);
			out.write(record);
		}
		for (Relocation relocation : relocations) {
			dc.putInt(record, 0, relocation.virtualAddress);
			dc.putInt(record, 4, relocation.symbol);
			dc.putShort(record, 8, relocation.type);
			out.write(record);
		}
	}
}
