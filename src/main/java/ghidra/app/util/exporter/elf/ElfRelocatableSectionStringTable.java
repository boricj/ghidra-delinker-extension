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
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.util.DataConverter;

public final class ElfRelocatableSectionStringTable extends ElfRelocatableSection {
	private final TreeMap<Integer, String> table = new TreeMap<>();
	private final Map<String, Integer> reverseTable = new HashMap<>();

	public ElfRelocatableSectionStringTable(ElfRelocatableObject elf, String name) {
		super(elf, name);

		this.table.put(0, "");
		this.reverseTable.put("", 0);
		this.index = elf.add(this);
	}

	@Override
	public int getShType() {
		return ElfSectionHeaderConstants.SHT_STRTAB;
	}

	@Override
	public long getShSize() {
		int length = 0;

		for (String string : table.values()) {
			length += string.length() + 1;
		}

		return length;
	}

	@Override
	public long getShAddrAlign() {
		return 1;
	}

	public int add(String string) {
		if (string == null) {
			throw new NullPointerException();
		}

		Entry<Integer, String> lastEntry = table.lastEntry();
		int nextKey = lastEntry.getKey() + lastEntry.getValue().length() + 1;
		table.put(nextKey, string);
		reverseTable.put(string, nextKey);
		return nextKey;
	}

	public int indexOf(String string) {
		return reverseTable.getOrDefault(string, 0);
	}

	@Override
	public void write(RandomAccessFile raf, DataConverter dc) throws IOException {
		for (String string : table.values()) {
			ByteBuffer stringBuffer = StandardCharsets.UTF_8.encode(string);
			raf.write(Arrays.copyOf(stringBuffer.array(), stringBuffer.limit()));
			raf.writeByte(0);
		}
	}
}
