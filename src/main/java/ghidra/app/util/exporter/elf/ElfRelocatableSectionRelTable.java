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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.util.DataConverter;
import ghidra.util.exception.NotYetImplementedException;

public final class ElfRelocatableSectionRelTable extends ElfRelocatableSection {
	private static final class Relocation {
		long offset;
		long type;
		long symindex;

		public Relocation(long offset, long type, long symindex) {
			this.offset = offset;
			this.type = type;
			this.symindex = symindex;
		}
	}

	private final List<Relocation> relocations = new ArrayList<>();
	private final ElfRelocatableSection section;
	private final ElfRelocatableSectionSymbolTable symtab;

	public ElfRelocatableSectionRelTable(ElfRelocatableObject elf, String name,
			ElfRelocatableSectionSymbolTable symtab, ElfRelocatableSection section) {
		super(elf, name);

		this.section = section;
		this.symtab = symtab;
		this.index = elf.add(this);
	}

	@Override
	public int getShType() {
		return ElfSectionHeaderConstants.SHT_REL;
	}

	@Override
	public long getShFlags() {
		return ElfSectionHeaderConstants.SHF_INFO_LINK;
	}

	@Override
	public long getShSize() {
		return getShEntSize() * relocations.size();
	}

	@Override
	public long getShEntSize() {
		if (getElfRelocatableObject().is32Bit()) {
			return 8;
		}
		else if (getElfRelocatableObject().is64Bit()) {
			return 16;
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
		return symtab.getIndex();
	}

	@Override
	public int getShInfo() {
		return section.getIndex();
	}

	@Override
	public void write(RandomAccessFile raf, DataConverter dc) throws IOException {
		if (getElfRelocatableObject().is32Bit()) {
			for (Relocation relocation : relocations) {
				raf.write(dc.getBytes((int) relocation.offset));
				raf.write(dc.getBytes((int) ((relocation.symindex << 8) | relocation.type)));
			}
		}
		else if (getElfRelocatableObject().is64Bit()) {
			for (Relocation relocation : relocations) {
				raf.write(dc.getBytes(relocation.offset));
				raf.write(dc.getBytes((relocation.symindex << 32) | relocation.type));
			}
		}
		else {
			throw new NotYetImplementedException();
		}
	}

	public ElfRelocatableSection getSection() {
		return section;
	}

	public ElfRelocatableSectionSymbolTable getSymtab() {
		return symtab;
	}

	public void add(long offset, long type, long symindex) {
		relocations.add(new Relocation(offset, type, symindex));
	}
}
