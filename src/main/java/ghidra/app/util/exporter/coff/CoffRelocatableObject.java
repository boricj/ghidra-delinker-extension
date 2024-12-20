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

import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.Writeable;
import ghidra.app.util.bin.format.pe.MachineConstants;
import ghidra.util.DataConverter;

public class CoffRelocatableObject implements Writeable {
	public final static int FILE_HEADER_OFFSET = 0;
	public final static int FILE_HEADER_SIZE = 20;
	public final static int SECTION_HEADERS_OFFSET = FILE_HEADER_OFFSET + FILE_HEADER_SIZE;

	private final List<CoffRelocatableSection> sections = new ArrayList<>();
	private final CoffRelocatableSymbolTable symtab;
	private final CoffRelocatableStringTable strtab;
	private final short machine;
	private final int timeDateStamp;
	private final int characteristics;

	public final static class Builder {
		private final CoffRelocatableSymbolTable symtab;
		private final CoffRelocatableStringTable strtab;
		private short machine = MachineConstants.IMAGE_FILE_MACHINE_UNKNOWN;
		private int timeDateStamp = 0;
		private int characteristics = 0;

		public Builder(CoffRelocatableSymbolTable symtab, CoffRelocatableStringTable strtab) {
			this.symtab = symtab;
			this.strtab = strtab;
		}

		public Builder setMachine(short machine) {
			this.machine = machine;
			return this;
		}

		public Builder setTimeDateStamp(int timeDateStamp) {
			this.timeDateStamp = timeDateStamp;
			return this;
		}

		public Builder setCharacteristics(int characteristics) {
			this.characteristics = characteristics;
			return this;
		}

		public CoffRelocatableObject build() {
			return new CoffRelocatableObject(this);
		}
	}

	private CoffRelocatableObject(CoffRelocatableObject.Builder builder) {
		this.symtab = builder.symtab;
		this.strtab = builder.strtab;
		this.machine = builder.machine;
		this.timeDateStamp = builder.timeDateStamp;
		this.characteristics = builder.characteristics;
	}

	public short getMachine() {
		return machine;
	}

	public void addSection(CoffRelocatableSection section) {
		sections.add(section);
	}

	public void layout() {
		int position =
			SECTION_HEADERS_OFFSET + sections.size() * CoffRelocatableSection.HEADER_SIZE;
		for (CoffRelocatableSection section : sections) {
			byte[] data = section.getData();
			if (data != null) {
				section.dataOffset = position;
				position += data.length;
			}
		}
		for (CoffRelocatableSection section : sections) {
			var relocationTable = section.getRelocationTable();
			relocationTable.offset = position;
			position += relocationTable.size();
		}
		symtab.offset = position;
	}

	@Override
	public void write(RandomAccessFile raf, DataConverter dc) throws IOException {
		layout();

		raf.seek(0);
		raf.setLength(0);
		byte[] fileHeader = new byte[FILE_HEADER_SIZE];
		dc.putShort(fileHeader, 0, machine);
		dc.putShort(fileHeader, 2, (short) sections.size());
		dc.putInt(fileHeader, 4, timeDateStamp);
		dc.putInt(fileHeader, 8, symtab.offset);
		dc.putInt(fileHeader, 12, symtab.getHeaderSymbolCount());
		dc.putShort(fileHeader, 16, (short) 0);
		dc.putShort(fileHeader, 18, (short) characteristics);
		raf.write(fileHeader);
		for (CoffRelocatableSection section : sections) {
			section.write(raf, dc);
		}
		for (CoffRelocatableSection section : sections) {
			raf.write(section.getData());
		}
		for (CoffRelocatableSection section : sections) {
			section.getRelocationTable().write(raf, dc);
		}
		symtab.write(raf, dc);
		strtab.write(raf, dc);
	}
}
