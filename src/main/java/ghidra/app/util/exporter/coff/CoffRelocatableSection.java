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
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.format.pe.SectionHeader;
import ghidra.util.DataConverter;

public class CoffRelocatableSection {
	public final static int HEADER_SIZE = 40;

	private final CoffRelocatableSectionRelocationTable relocationTable;
	private final String shortName;
	private final int longNameIndex;
	private final int virtualSize;
	private final int virtualAddress;
	private final int characteristics;
	private final byte[] data;
	protected int dataOffset;

	public final static class Builder {
		private final CoffRelocatableSectionRelocationTable relocationTable;
		private final String shortName;
		private final int longNameIndex;
		private int virtualSize = 0;
		private int virtualAddress = 0;
		private int characteristics = 0;
		private byte[] data = null;

		public Builder(CoffRelocatableSectionRelocationTable relocationTable,
				CoffRelocatableStringTable stringTable, String name) {
			this.relocationTable = relocationTable;
			if (name.length() <= 8) {
				this.shortName = name;
				this.longNameIndex = 0;
			}
			else {
				this.shortName = null;
				this.longNameIndex = stringTable.add(name);
			}
		}

		public Builder setVirtualSize(int virtualSize) {
			this.virtualSize = virtualSize;
			return this;
		}

		public Builder setVirtualAddress(int virtualAddress) {
			this.virtualAddress = virtualAddress;
			return this;
		}

		public Builder setCharacteristics(int characteristics) {
			this.characteristics = characteristics;
			return this;
		}

		public Builder setData(byte[] data) {
			this.data = data;
			return this;
		}

		public CoffRelocatableSection build() {
			return new CoffRelocatableSection(this);
		}
	}

	private CoffRelocatableSection(Builder builder) {
		this.relocationTable = builder.relocationTable;
		this.shortName = builder.shortName;
		this.longNameIndex = builder.longNameIndex;
		this.virtualSize = builder.virtualSize;
		this.virtualAddress = builder.virtualAddress;
		this.characteristics = builder.characteristics;
		this.data = builder.data;
	}

	public CoffRelocatableSectionRelocationTable getRelocationTable() {
		return relocationTable;
	}

	public byte[] getData() {
		return data;
	}

	public void write(DataOutput out, DataConverter dc) throws IOException {
		byte[] header = new byte[HEADER_SIZE];
		if (shortName != null) {
			byte[] nameBytes = shortName.getBytes(StandardCharsets.UTF_8);
			System.arraycopy(nameBytes, 0, header, 0, nameBytes.length);
		}
		else if (longNameIndex > 0) {
			byte[] nameBytes = String.format("/%d", longNameIndex).getBytes(StandardCharsets.UTF_8);
			System.arraycopy(nameBytes, 0, header, 0, nameBytes.length);
		}
		else {
			throw new RuntimeException("Couldn't serialize section name");
		}
		dc.putInt(header, 8, virtualSize);
		dc.putInt(header, 12, virtualAddress);
		if (data != null) {
			dc.putInt(header, 16, data.length);
			dc.putInt(header, 20, dataOffset);
		}
		else {
			dc.putInt(header, 16, 0);
			dc.putInt(header, 20, 0);
		}
		dc.putInt(header, 24, relocationTable.offset);
		dc.putInt(header, 28, 0);
		dc.putShort(header, 32, relocationTable.headerCount());
		dc.putShort(header, 34, (short) 0);
		int sectionCharacteristics = characteristics;
		if (relocationTable.linkOverflow()) {
			sectionCharacteristics |= SectionHeader.IMAGE_SCN_LNK_NRELOC_OVFL;
		}
		dc.putInt(header, 36, sectionCharacteristics);
		out.write(header);
	}
}
