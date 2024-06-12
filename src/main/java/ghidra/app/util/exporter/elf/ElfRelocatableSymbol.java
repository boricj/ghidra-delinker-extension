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

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.List;

import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.util.DataConverter;
import ghidra.util.exception.NotYetImplementedException;

public final class ElfRelocatableSymbol implements Comparable<ElfRelocatableSymbol> {
	private final String name;
	private final int st_name;
	private final long value;
	private final long size;
	private final byte info;
	private final byte other;
	private final short shndx;

	private static final List<Byte> LOCAL_NONSECTION_TYPE_ORDER = List.of(
		ElfSymbol.STT_NOTYPE,
		ElfSymbol.STT_FILE,
		ElfSymbol.STT_SECTION);

	protected ElfRelocatableSymbol(String name, int st_name, long value, long size, byte info,
			byte other,
			short shndx) {
		this.name = name;
		this.st_name = st_name;
		this.value = value;
		this.size = size;
		this.info = info;
		this.other = other;
		this.shndx = shndx;
	}

	public String getName() {
		return name;
	}

	public byte getType() {
		return (byte) (info & 0x0F);
	}

	public byte getBinding() {
		return (byte) (info >> 4);
	}

	@Override
	public int compareTo(ElfRelocatableSymbol other) {
		// Put local symbols first.
		if (getBinding() != other.getBinding()) {
			return getBinding() - other.getBinding();
		}
		if (getBinding() == ElfSymbol.STB_LOCAL) {
			// Put symbols not inside a section first.
			if (insideSection() != other.insideSection()) {
				return Boolean.compare(insideSection(), other.insideSection());
			}
			// Order symbols not inside a section.
			else if (insideSection() == false && (getType() != other.getType())) {
				return LOCAL_NONSECTION_TYPE_ORDER.indexOf(getType()) -
					LOCAL_NONSECTION_TYPE_ORDER.indexOf(other.getType());
			}
		}
		// Order by section.
		if (shndx != other.shndx) {
			return (shndx != ElfSectionHeaderConstants.SHN_UNDEF ? shndx : 0x7fff) -
				(other.shndx != ElfSectionHeaderConstants.SHN_UNDEF ? other.shndx : 0x7fff);
		}
		// Order by address.
		if (value != other.value) {
			return (int) (value - other.value);
		}
		// Order by name (for external symbols).
		return name.compareTo(other.name);
	}

	public byte[] toBytes(DataConverter dc, ElfRelocatableSectionSymbolTable symtab)
			throws IOException {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(os);

		if (symtab.getElfRelocatableObject().is32Bit()) {
			dos.write(dc.getBytes(st_name));
			dos.write(dc.getBytes((int) value));
			dos.write(dc.getBytes((int) size));
			dos.writeByte(info);
			dos.writeByte(other);
			dos.write(dc.getBytes(shndx));
		}
		else if (symtab.getElfRelocatableObject().is64Bit()) {
			dos.write(dc.getBytes(st_name));
			dos.writeByte(info);
			dos.writeByte(other);
			dos.write(dc.getBytes(shndx));
			dos.write(dc.getBytes(value));
			dos.write(dc.getBytes(size));
		}
		else {
			throw new NotYetImplementedException();
		}

		return os.toByteArray();
	}

	private boolean insideSection() {
		return getType() == ElfSymbol.STT_FUNC || getType() == ElfSymbol.STT_OBJECT ||
			(getType() == ElfSymbol.STT_NOTYPE && shndx != ElfSectionHeaderConstants.SHN_UNDEF);
	}
}
