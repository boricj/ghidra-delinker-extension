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

public class CoffRelocatableSectionRelocationTable {
	public final static int RECORD_SIZE = 10;

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

	public static final class Builder {
		private final List<Relocation> relocations = new ArrayList<>();

		public void addRelocation(Relocation relocation) {
			relocations.add(relocation);
		}

		public CoffRelocatableSectionRelocationTable build() {
			return new CoffRelocatableSectionRelocationTable(this);
		}
	}

	private final Relocation[] relocations;

	private CoffRelocatableSectionRelocationTable(Builder builder) {
		relocations = builder.relocations.toArray(new Relocation[0]);
	}

	public boolean linkOverflow() {
		return relocations.length > 65535;
	}

	public short headerCount() {
		if (linkOverflow()) {
			return (short) 65535;
		}
		return (short) relocations.length;
	}

	public int size() {
		return (linkOverflow() ? RECORD_SIZE : 0) + (relocations.length * RECORD_SIZE);
	}

	public void write(DataOutput out, DataConverter dc) throws IOException {
		byte[] record = new byte[RECORD_SIZE];
		if (linkOverflow()) {
			dc.putInt(record, 0, relocations.length);
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
