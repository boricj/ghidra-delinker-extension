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

import ghidra.util.DataConverter;

public class CoffRelocatableSymbolAuxSectionDefinition implements CoffRelocatableSymbolAux {
	private final int length;
	private final short numRelocations;

	public CoffRelocatableSymbolAuxSectionDefinition(int length, short numRelocations) {
		this.length = length;
		this.numRelocations = numRelocations;
	}

	@Override
	public byte[] toBytes(DataConverter dc) {
		byte[] symbol = new byte[CoffRelocatableSymbol.SYMBOL_SIZE];
		dc.putInt(symbol, 0, length);
		dc.putShort(symbol, numRelocations);
		return symbol;
	}

	@Override
	public int symbolCount() {
		return 1;
	}
}
