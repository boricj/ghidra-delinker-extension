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
import java.util.List;
import java.util.HashMap;
import java.util.TreeMap;

import ghidra.app.util.bin.format.coff.CoffSymbolSectionNumber;
import ghidra.app.util.bin.format.coff.CoffSymbolStorageClass;
import ghidra.util.DataConverter;

public class CoffRelocatableSymbolTable {
	private final CoffRelocatableStringTable strtab;
	private final TreeMap<Integer, CoffRelocatableSymbol> symtab = new TreeMap<>();
	private final HashMap<String, Integer> lookup = new HashMap<>();
	private int headerSymbolCount = 0;
	protected int offset;

	public CoffRelocatableSymbolTable(CoffRelocatableStringTable strtab) {
		this.strtab = strtab;
	}

	public int getSymbolNumber(String name) {
		return lookup.getOrDefault(name, -1);
	}

	private int addSymbol(CoffRelocatableSymbol symbol) {
		int symbolNumber = headerSymbolCount;
		symtab.put(symbolNumber, symbol);
		headerSymbolCount += symbol.symbolCount();
		return symbolNumber;
	}

	public void addFileSymbol(String fileName) {
		var fileSymbol = new CoffRelocatableSymbol(strtab, ".file", 0, (short) 0,
			CoffSymbolSectionNumber.N_DEBUG, (byte) CoffSymbolStorageClass.C_FILE,
			List.of(new CoffRelocatableSymbolAuxFile(fileName)));
		addSymbol(fileSymbol);
	}

	public void addSectionSymbol(String name, short sectionNumber, int length,
			short numRelocations) {
		var symbol =
			new CoffRelocatableSymbol(strtab, name, 0, (short) 0, sectionNumber,
				(byte) CoffSymbolStorageClass.C_STAT,
				List.of(new CoffRelocatableSymbolAuxSectionDefinition(length, numRelocations)));
		lookup.put(name, addSymbol(symbol));
	}

	public void addDefinedSymbol(String originalName, String name, short sectionNumber, int offset,
			short type, byte storageClass) {
		var symbol = new CoffRelocatableSymbol(strtab, name, (int) offset, type, sectionNumber,
			storageClass);
		lookup.put(originalName, addSymbol(symbol));
	}

	public void addUndefinedSymbol(String originalName, String name) {
		var symbol = new CoffRelocatableSymbol(strtab, name, 0, (short) 0x20,
			CoffSymbolSectionNumber.N_UNDEF, (byte) CoffSymbolStorageClass.C_EXT);
		lookup.put(originalName, addSymbol(symbol));
	}

	public int getHeaderSymbolCount() {
		return headerSymbolCount;
	}

	public void write(DataOutput out, DataConverter dc) throws IOException {
		for (var value : symtab.values()) {
			value.write(out, dc);
		}
	}
}
