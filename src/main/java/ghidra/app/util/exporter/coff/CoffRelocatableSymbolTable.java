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
import java.util.TreeMap;

import ghidra.app.util.bin.format.coff.CoffSymbolStorageClass;
import ghidra.util.DataConverter;

public class CoffRelocatableSymbolTable {
	private final TreeMap<Integer, CoffRelocatableSymbol> symbolTable;
	private final int headerSymbolCount;
	protected int offset;

	public final static class Builder {
		private final CoffRelocatableStringTable stringTable;
		private final TreeMap<Integer, CoffRelocatableSymbol> symbolTable = new TreeMap<>();
		private int headerSymbolCount = 0;

		public int addSymbol(CoffRelocatableSymbol symbol) {
			int symbolNumber = headerSymbolCount;
			symbolTable.put(symbolNumber, symbol);
			headerSymbolCount += symbol.symbolCount();
			return symbolNumber;
		}

		public int addFileSymbol(String fileName) {
			var fileSymbol = new CoffRelocatableSymbol.Builder(stringTable, ".file")
					.setType((short) 0)
					.setSectionNumber((short) 65534)
					.setStorageClass((byte) 103)
					.addAuxSymbol(new CoffRelocatableSymbolAuxFile(fileName))
					.build();
			return addSymbol(fileSymbol);
		}

		public int addSectionSymbol(String sectionName, short sectionNumber, int length,
				short numRelocations) {
			var sectionSymbol = new CoffRelocatableSymbol.Builder(stringTable, sectionName)
					.setType((short) 0)
					.setSectionNumber(sectionNumber)
					.setStorageClass((byte) CoffSymbolStorageClass.C_STAT)
					.addAuxSymbol(
						new CoffRelocatableSymbolAuxSectionDefinition(length, numRelocations))
					.build();
			return addSymbol(sectionSymbol);
		}

		public Builder(CoffRelocatableStringTable stringTable) {
			this.stringTable = stringTable;
		}

		public CoffRelocatableSymbolTable build() {
			return new CoffRelocatableSymbolTable(this);
		}
	}

	private CoffRelocatableSymbolTable(Builder builder) {
		symbolTable = builder.symbolTable;
		headerSymbolCount = builder.headerSymbolCount;
	}

	public int getHeaderSymbolCount() {
		return headerSymbolCount;
	}

	public void write(DataOutput out, DataConverter dc) throws IOException {
		for (var value : symbolTable.values()) {
			value.write(out, dc);
		}
	}
}
