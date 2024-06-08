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
import java.util.ArrayList;

import ghidra.util.DataConverter;

public class CoffRelocatableSymbol {
	public final static int SYMBOL_SIZE = 18;

	private final String shortName;
	private final int longNameIndex;
	private final int value;
	private final short sectionNumber;
	private final short type;
	private final byte storageClass;
	private final CoffRelocatableSymbolAux[] auxSymbols;
	private final int auxSymbolCount;
	protected int index;

	public final static class Builder {
		private final String shortName;
		private final int longNameIndex;
		private final ArrayList<CoffRelocatableSymbolAux> auxSymbols = new ArrayList<>();
		private int auxSymbolCount = 0;

		private int value;
		private short sectionNumber;
		private short type;
		private byte storageClass;

		public Builder setValue(int value) {
			this.value = value;
			return this;
		}

		public Builder setSectionNumber(short sectionNumber) {
			this.sectionNumber = sectionNumber;
			return this;
		}

		public Builder setType(short type) {
			this.type = type;
			return this;
		}

		public Builder setStorageClass(byte storageClass) {
			this.storageClass = storageClass;
			return this;
		}

		public Builder addAuxSymbol(CoffRelocatableSymbolAux symbol) {
			auxSymbols.add(symbol);
			auxSymbolCount += symbol.symbolCount();
			return this;
		}

		public Builder(CoffRelocatableStringTable stringTable, String name) {
			if (name.getBytes(StandardCharsets.UTF_8).length <= 8) {
				this.shortName = name;
				this.longNameIndex = 0;
			}
			else {
				this.shortName = null;
				this.longNameIndex = stringTable.add(name);
			}
		}

		public CoffRelocatableSymbol build() {
			return new CoffRelocatableSymbol(this);
		}
	}

	private CoffRelocatableSymbol(Builder builder) {
		this.shortName = builder.shortName;
		this.longNameIndex = builder.longNameIndex;
		this.value = builder.value;
		this.sectionNumber = builder.sectionNumber;
		this.type = builder.type;
		this.storageClass = builder.storageClass;
		this.auxSymbols = builder.auxSymbols.toArray(new CoffRelocatableSymbolAux[0]);
		this.auxSymbolCount = builder.auxSymbolCount;
	}

	public int symbolCount() {
		return 1 + auxSymbolCount;
	}

	public void write(DataOutput out, DataConverter dc) throws IOException {
		byte[] symbol = new byte[SYMBOL_SIZE];
		if (shortName != null) {
			byte[] nameBytes = shortName.getBytes(StandardCharsets.UTF_8);
			System.arraycopy(nameBytes, 0, symbol, 0, nameBytes.length);
		}
		else if (longNameIndex > 0) {
			dc.putInt(symbol, 0, 0);
			dc.putInt(symbol, 4, longNameIndex);
		}
		else {
			throw new RuntimeException("Couldn't serialize symbol name");
		}
		dc.putInt(symbol, 8, value);
		dc.putShort(symbol, 12, sectionNumber);
		dc.putShort(symbol, 14, type);
		symbol[16] = storageClass;
		symbol[17] = (byte) auxSymbolCount;
		out.write(symbol);

		for (CoffRelocatableSymbolAux aux : auxSymbols) {
			out.write(aux.toBytes(dc));
		}
	}
}
