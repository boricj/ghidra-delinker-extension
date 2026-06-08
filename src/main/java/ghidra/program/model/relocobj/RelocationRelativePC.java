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
	private final int trailingBytes;

	protected RelocationRelativePC(RelocationTable relocationTable, Address address, int width,
			Address target, long addend) {
		this(relocationTable, address, width, target, addend, true);
	}

	protected RelocationRelativePC(RelocationTable relocationTable, Address address, int width,
			long bitmask, Address target, long addend) {
		this(relocationTable, address, width, bitmask, target, addend, true);
	}

	protected RelocationRelativePC(RelocationTable relocationTable, Address address, int width,
			Address target, long addend, boolean isTransparent) {
		this(relocationTable, address, width, target, addend, isTransparent, 0);
	}

	protected RelocationRelativePC(RelocationTable relocationTable, Address address, int width,
			long bitmask, Address target, long addend, boolean isTransparent) {
		this(relocationTable, address, width, bitmask, target, addend, isTransparent, 0);
	}

	protected RelocationRelativePC(RelocationTable relocationTable, Address address, int width,
			Address target, long addend, boolean isTransparent, int trailingBytes) {
		super(relocationTable, address, width, target, addend);

		this.isTransparent = isTransparent;
		this.trailingBytes = trailingBytes;
	}

	protected RelocationRelativePC(RelocationTable relocationTable, Address address, int width,
			long bitmask, Address target, long addend, boolean isTransparent, int trailingBytes) {
		super(relocationTable, address, width, bitmask, target, addend);

		this.isTransparent = isTransparent;
		this.trailingBytes = trailingBytes;
	}

	/**
	 * Number of instruction bytes following the relocated field (for example a trailing
	 * immediate operand). For x86-64 COFF this selects the IMAGE_REL_AMD64_REL32_N variant,
	 * whose PC reference point is the end of the instruction rather than the end of the
	 * field. Zero for the common case where the relocated field is the last operand.
	 *
	 * @return the number of trailing instruction bytes after the relocated field
	 */
	public int getTrailingBytes() {
		return trailingBytes;
	}

	@Override
	public boolean isTransparent() {
		return isTransparent;
	}
}
