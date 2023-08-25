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
package ghidra.program.model.relocobj;

import ghidra.program.model.address.Address;

public class RelocationRelativeSymbol extends AbstractRelocationBitmaskShifted {
	private final String relativeSymbolName;

	protected RelocationRelativeSymbol(RelocationTable relocationTable, Address address, int width,
			String symbolName, long addend, String relativeSymbolName) {
		super(relocationTable, address, width, symbolName, addend);

		this.relativeSymbolName = relativeSymbolName;
	}

	protected RelocationRelativeSymbol(RelocationTable relocationTable, Address address, int width,
			long bitmask, int shift, String symbolName, long addend, String relativeSymbolName) {
		super(relocationTable, address, width, bitmask, shift, symbolName, addend);

		this.relativeSymbolName = relativeSymbolName;
	}

	public String getRelativeSymbolName() {
		return relativeSymbolName;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof RelocationRelativeSymbol)) {
			return false;
		}

		RelocationRelativeSymbol rel = (RelocationRelativeSymbol) obj;
		if (!relativeSymbolName.equals(rel.getRelativeSymbolName())) {
			return false;
		}

		return super.equals(obj);
	}
}
