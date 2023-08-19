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

import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.util.DataConverter;

public final class ElfRelocatableSectionProgBits extends ElfRelocatableSection {
	private final byte[] bytes;
	private final long flags;

	public ElfRelocatableSectionProgBits(ElfRelocatableObject elf, String name, byte[] bytes,
			long flags) {
		super(elf, name);

		this.bytes = bytes;
		this.flags = flags;
		this.index = elf.add(this);
	}

	@Override
	public int getShType() {
		return ElfSectionHeaderConstants.SHT_PROGBITS;
	}

	@Override
	public long getShSize() {
		return bytes.length;
	}

	@Override
	public long getShAddrAlign() {
		return 16;
	}

	@Override
	public long getShFlags() {
		return flags;
	}

	@Override
	public void write(RandomAccessFile raf, DataConverter dc) throws IOException {
		raf.write(bytes);
	}
}
