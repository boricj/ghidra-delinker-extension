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

public class RelocationRelativePC extends AbstractRelocationBitmask {
	private final boolean isTransparent;

	protected RelocationRelativePC(RelocationTable relocationTable, Address address, int width,
			String symbolName, long addend) {
		this(relocationTable, address, width, symbolName, addend, true);
	}

	protected RelocationRelativePC(RelocationTable relocationTable, Address address, int width,
			long bitmask, String symbolName, long addend) {
		this(relocationTable, address, width, bitmask, symbolName, addend, true);
	}

	protected RelocationRelativePC(RelocationTable relocationTable, Address address, int width,
			String symbolName, long addend, boolean isTransparent) {
		super(relocationTable, address, width, symbolName, addend);

		this.isTransparent = isTransparent;
	}

	protected RelocationRelativePC(RelocationTable relocationTable, Address address, int width,
			long bitmask, String symbolName, long addend, boolean isTransparent) {
		super(relocationTable, address, width, bitmask, symbolName, addend);

		this.isTransparent = isTransparent;
	}

	@Override
	public boolean isTransparent() {
		return isTransparent;
	}
}
