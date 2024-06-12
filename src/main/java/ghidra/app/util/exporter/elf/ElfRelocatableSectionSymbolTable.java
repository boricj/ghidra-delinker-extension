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
package ghidra.app.util.exporter.elf;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.HashMap;
import java.util.TreeSet;

import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.util.DataConverter;
import ghidra.util.exception.NotYetImplementedException;

public final class ElfRelocatableSectionSymbolTable extends ElfRelocatableSection {
	private final TreeSet<ElfRelocatableSymbol> symbols = new TreeSet<>();
	private final HashMap<String, ElfRelocatableSymbol> lookup = new HashMap<>();
	private final ElfRelocatableSectionStringTable strtab;

	public ElfRelocatableSectionSymbolTable(ElfRelocatableObject elf, String name,
			ElfRelocatableSectionStringTable strtab) {
		super(elf, name);

		this.strtab = strtab;
		this.index = elf.add(this);

		addNullSymbol();
	}

	@Override
	public int getShType() {
		return ElfSectionHeaderConstants.SHT_SYMTAB;
	}

	@Override
	public long getShSize() {
		return getShEntSize() * symbols.size();
	}

	@Override
	public long getShEntSize() {
		if (getElfRelocatableObject().is32Bit()) {
			return 16;
		}
		else if (getElfRelocatableObject().is64Bit()) {
			return 24;
		}

		throw new NotYetImplementedException();
	}

	@Override
	public long getShAddrAlign() {
		if (getElfRelocatableObject().is32Bit()) {
			return 4;
		}
		else if (getElfRelocatableObject().is64Bit()) {
			return 8;
		}

		throw new NotYetImplementedException();
	}

	@Override
	public int getShLink() {
		return strtab.getIndex();
	}

	@Override
	public int getShInfo() {
		int index = 0;

		for (ElfRelocatableSymbol symbol : symbols) {
			if (symbol.getBinding() != ElfSymbol.STB_LOCAL) {
				break;
			}

			index = index + 1;
		}

		return index;
	}

	@Override
	public void write(RandomAccessFile raf, DataConverter dc) throws IOException {
		for (ElfRelocatableSymbol symbol : symbols) {
			raf.write(symbol.toBytes(dc, this));
		}
	}

	public int indexOf(ElfRelocatableSymbol symbol) {
		return symbols.headSet(symbol).size();
	}

	public ElfRelocatableSymbol addNullSymbol() {
		byte info = ElfSymbol.STT_NOTYPE | (ElfSymbol.STB_LOCAL << 4);
		ElfRelocatableSymbol symbol =
			new ElfRelocatableSymbol("", 0, 0, 0, info, ElfSymbol.STV_DEFAULT,
				ElfSectionHeaderConstants.SHN_UNDEF);
		symbols.add(symbol);
		return symbol;
	}

	public ElfRelocatableSymbol addFileSymbol(String name) {
		int st_name = strtab.add(name);
		byte info = ElfSymbol.STT_FILE | (ElfSymbol.STB_LOCAL << 4);
		ElfRelocatableSymbol symbol =
			new ElfRelocatableSymbol(name, st_name, 0, 0, info, ElfSymbol.STV_DEFAULT,
				ElfSectionHeaderConstants.SHN_ABS);
		symbols.add(symbol);
		return symbol;
	}

	public ElfRelocatableSymbol addSectionSymbol(ElfRelocatableSection section) {
		byte info = ElfSymbol.STT_SECTION | (ElfSymbol.STB_LOCAL << 4);
		String name = section.getName();
		short shndx = (short) section.getIndex();
		ElfRelocatableSymbol symbol =
			new ElfRelocatableSymbol(name, 0, 0, 0, info, ElfSymbol.STV_DEFAULT,
				shndx);
		symbols.add(symbol);
		lookup.put(name, symbol);
		return symbol;
	}

	public ElfRelocatableSymbol addDefinedSymbol(ElfRelocatableSection section, String name,
			byte visibility, byte type, long size, long offset) {
		int st_name = strtab.add(name);
		byte info = (byte) (type | (visibility << 4));
		short shndx = (short) section.getIndex();
		ElfRelocatableSymbol symbol =
			new ElfRelocatableSymbol(name, st_name, offset, size, info, ElfSymbol.STV_DEFAULT,
				shndx);
		symbols.add(symbol);
		lookup.put(name, symbol);
		return symbol;
	}

	public ElfRelocatableSymbol addExternalSymbol(String name) {
		int st_name = strtab.add(name);
		byte info = (byte) (ElfSymbol.STT_NOTYPE | (ElfSymbol.STB_GLOBAL << 4));
		short shndx = (short) ElfSectionHeaderConstants.SHN_UNDEF;
		ElfRelocatableSymbol symbol =
			new ElfRelocatableSymbol(name, st_name, 0, 0, info, ElfSymbol.STV_DEFAULT, shndx);
		symbols.add(symbol);
		lookup.put(name, symbol);
		return symbol;
	}

	public ElfRelocatableSymbol get(String name) {
		return lookup.get(name);
	}
}
