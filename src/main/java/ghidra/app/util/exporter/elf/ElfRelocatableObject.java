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
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.ByteArrayConverter;
import ghidra.app.util.bin.format.Writeable;
import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.util.DataConverter;
import ghidra.util.exception.NotYetImplementedException;

public final class ElfRelocatableObject implements ByteArrayConverter, Writeable {
	private static final int PAD_LENGTH = 7;

	private final String fileName;
	private final List<ElfRelocatableSection> sections = new ArrayList<>();
	private final Map<ElfRelocatableSection, Long> sectionOffsets = new HashMap<>();

	private final Builder builder;

	private ElfRelocatableSectionStringTable shstrtab = null;

	public final static class Builder {
		final String fileName;

		byte e_ident_class = ElfConstants.ELF_CLASS_NONE;
		byte e_ident_data = ElfConstants.ELF_DATA_NONE;
		byte e_ident_version = ElfConstants.EV_CURRENT;
		byte e_ident_osabi = ElfConstants.ELFOSABI_NONE;
		byte e_ident_abiversion = 0;
		short e_type = ElfConstants.ET_NONE;
		short e_machine = ElfConstants.EM_NONE;
		int e_version = ElfConstants.EV_CURRENT;
		long e_entry = 0;
		int e_flags = 0;

		public Builder(String fileName) {
			this.fileName = fileName;
		}

		public Builder setClass(byte class_) {
			e_ident_class = class_;
			return this;
		}

		public Builder setData(byte data) {
			e_ident_data = data;
			return this;
		}

		public Builder setType(short type) {
			e_type = type;
			return this;
		}

		public Builder setMachine(short machine) {
			e_machine = machine;
			return this;
		}

		public ElfRelocatableObject build() {
			return new ElfRelocatableObject(fileName, this);
		}
	}

	ElfRelocatableObject(String fileName, Builder builder) {
		this.fileName = fileName;
		this.builder = builder;

		// Create null section.
		new ElfRelocatableSectionNull(this);
	}

	public byte getElfClass() {
		return builder.e_ident_class;
	}

	public byte getElfData() {
		return builder.e_ident_data;
	}

	public byte getElfOsabi() {
		return builder.e_ident_osabi;
	}

	public byte getElfAbiversion() {
		return builder.e_ident_abiversion;
	}

	public short getElfType() {
		return builder.e_type;
	}

	public short getElfMachine() {
		return builder.e_machine;
	}

	public DataConverter getDataConverter() {
		if (builder.e_ident_data == ElfConstants.ELF_DATA_BE) {
			return DataConverter.getInstance(true);
		}
		else if (builder.e_ident_data == ElfConstants.ELF_DATA_LE) {
			return DataConverter.getInstance(false);
		}

		throw new NotYetImplementedException();
	}

	public boolean is32Bit() {
		return builder.e_ident_class == ElfConstants.ELF_CLASS_32;
	}

	public boolean is64Bit() {
		return builder.e_ident_class == ElfConstants.ELF_CLASS_64;
	}

	public long getOffsetOf(ElfRelocatableSection section) {
		return sectionOffsets.getOrDefault(section, 0L);
	}

	public String getFileName() {
		return fileName;
	}

	public void setShStrTab(ElfRelocatableSectionStringTable shstrtab) {
		this.shstrtab = shstrtab;
	}

	public ElfRelocatableSectionStringTable getShStrTab() {
		return shstrtab;
	}

	@Override
	public void write(RandomAccessFile raf, DataConverter dc) throws IOException {
		raf.seek(0);
		raf.setLength(0);
		raf.write(toBytes(dc));

		for (ElfRelocatableSection section : sections) {
			raf.write(section.toBytes(dc));
		}

		for (ElfRelocatableSection section : sections) {
			raf.seek(getOffsetOf(section));
			section.write(raf, dc);
		}
	}

	@Override
	public byte[] toBytes(DataConverter dc) throws IOException {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(os);

		long e_phoff = 0;
		long e_shoff = is32Bit() ? 52 : 64;
		short e_ehsize = (short) e_shoff;
		short e_phentsize = 0;
		short e_phnum = 0;
		short e_shentsize = (short) (is32Bit() ? 40 : 64);
		short e_shnum = (short) sections.size();
		short e_shstrndx = (short) (shstrtab != null ? shstrtab.getIndex() : 0);

		dos.writeByte(ElfConstants.MAGIC_NUM);
		dos.write(ElfConstants.MAGIC_STR.getBytes());
		dos.writeByte(builder.e_ident_class);
		dos.writeByte(builder.e_ident_data);
		dos.writeByte(builder.e_ident_version);
		dos.writeByte(builder.e_ident_osabi);
		dos.writeByte(builder.e_ident_abiversion);
		dos.write(new byte[PAD_LENGTH]);
		dos.write(dc.getBytes(builder.e_type));
		dos.write(dc.getBytes(builder.e_machine));
		dos.write(dc.getBytes(builder.e_version));

		if (is32Bit()) {
			dos.write(dc.getBytes((int) builder.e_entry));
			dos.write(dc.getBytes((int) e_phoff));
			dos.write(dc.getBytes((int) e_shoff));
		}
		else if (is64Bit()) {
			dos.write(dc.getBytes(builder.e_entry));
			dos.write(dc.getBytes(e_phoff));
			dos.write(dc.getBytes(e_shoff));
		}
		else {
			throw new NotYetImplementedException();
		}

		dos.write(dc.getBytes(builder.e_flags));
		dos.write(dc.getBytes(e_ehsize));
		dos.write(dc.getBytes(e_phentsize));
		dos.write(dc.getBytes((short) e_phnum));
		dos.write(dc.getBytes(e_shentsize));
		dos.write(dc.getBytes((short) e_shnum));
		dos.write(dc.getBytes((short) e_shstrndx));

		return os.toByteArray();
	}

	public void layout() {
		long offset;

		if (is32Bit()) {
			offset = 52 + sections.size() * 40;
		}
		else if (is64Bit()) {
			offset = 64 + sections.size() * 64;
		}
		else {
			throw new NotYetImplementedException();
		}

		sectionOffsets.clear();
		for (ElfRelocatableSection section : sections) {
			if (section instanceof ElfRelocatableSectionNull ||
				section instanceof ElfRelocatableSectionNoBits) {
				continue;
			}

			long alignment = section.getShAddrAlign();
			if (alignment > 0) {
				offset = ((offset + alignment - 1) / alignment) * alignment;
			}
			sectionOffsets.put(section, offset);
			offset += section.getShSize();
		}

		if (shstrtab != null) {
			for (ElfRelocatableSection section : sections.subList(1, sections.size())) {
				shstrtab.add(section.getName());
			}
		}
	}

	protected int add(ElfRelocatableSection section) {
		int index = sections.size();
		sections.add(section);
		return index;
	}
}
