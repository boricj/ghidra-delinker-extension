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
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

import ghidra.util.DataConverter;

public final class CoffRelocatableStringTable {
	private final TreeMap<Integer, byte[]> table = new TreeMap<>();
	private final Map<String, Integer> reverseTable = new HashMap<>();
	private int length = 4;

	public long getLength() {
		return length;
	}

	public int add(String string) {
		if (string == null) {
			throw new NullPointerException();
		}

		int index = indexOf(string);
		if (index != 0) {
			return index;
		}

		ByteBuffer stringBuffer = StandardCharsets.UTF_8.encode(string);
		byte[] bytes = Arrays.copyOf(stringBuffer.array(), stringBuffer.limit());

		int nextKey = length;
		table.put(nextKey, bytes);
		reverseTable.put(string, nextKey);
		length += bytes.length + 1;
		return nextKey;
	}

	public int indexOf(String string) {
		return reverseTable.getOrDefault(string, 0);
	}

	public void write(DataOutput out, DataConverter dc) throws IOException {
		byte[] header = new byte[4];
		dc.putInt(header, length);
		out.write(header);
		for (byte[] stringBuffer : table.values()) {
			out.write(stringBuffer);
			out.writeByte(0);
		}
	}
}
