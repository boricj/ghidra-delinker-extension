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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import ghidra.util.DataConverter;

public class CoffRelocatableSymbolAuxFile implements CoffRelocatableSymbolAux {
	private final byte[] nameBytes;

	public CoffRelocatableSymbolAuxFile(String name) {
		ByteBuffer nameBuffer = StandardCharsets.UTF_8.encode(name);
		int paddedLen = ((nameBuffer.limit() + 17) / 18) * 18;

		this.nameBytes = Arrays.copyOf(nameBuffer.array(), paddedLen);
	}

	@Override
	public byte[] toBytes(DataConverter dc) {
		return nameBytes;
	}

	@Override
	public int symbolCount() {
		return nameBytes.length / 18;
	}
}
