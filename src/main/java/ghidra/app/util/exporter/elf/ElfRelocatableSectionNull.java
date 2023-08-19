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

public class ElfRelocatableSectionNull extends ElfRelocatableSection {
	public ElfRelocatableSectionNull(ElfRelocatableObject elf) {
		super(elf, "");
		this.index = elf.add(this);
	}

	@Override
	public int getShType() {
		return ElfSectionHeaderConstants.SHT_NULL;
	}

	@Override
	public long getShOffset() {
		return 0;
	}

	@Override
	public long getShSize() {
		return 0;
	}

	@Override
	public long getShAddrAlign() {
		return 0;
	}

	@Override
	public void write(RandomAccessFile raf, DataConverter dc) throws IOException {
	}
}
