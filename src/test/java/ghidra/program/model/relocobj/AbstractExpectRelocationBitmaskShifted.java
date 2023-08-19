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

public abstract class AbstractExpectRelocationBitmaskShifted extends AbstractExpectRelocation {
	private final long address;
	private final int width;
	private final long bitmask;
	private final int shift;
	private final String symbolName;
	private final long addend;

	public AbstractExpectRelocationBitmaskShifted(long address, int width, String symbolName,
			long addend) {
		this(address, width, Relocation.getBitmask(width), 0, symbolName, addend);
	}

	public AbstractExpectRelocationBitmaskShifted(long address, int width, long bitmask, int shift,
			String symbolName, long addend) {
		this.address = address;
		this.width = width;
		this.bitmask = bitmask;
		this.shift = shift;
		this.symbolName = symbolName;
		this.addend = addend;
	}

	// This equals() method is intentionally not implementing an equivalence relation.
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof AbstractRelocationBitmaskShifted)) {
			return false;
		}

		AbstractRelocationBitmaskShifted relocation = (AbstractRelocationBitmaskShifted) obj;
		return address == relocation.getAddress().getOffset() && width == relocation.getWidth() &&
			bitmask == relocation.getBitmask() && shift == relocation.getShift() &&
			symbolName.equals(relocation.getSymbolName()) && addend == relocation.getAddend();
	}
}
