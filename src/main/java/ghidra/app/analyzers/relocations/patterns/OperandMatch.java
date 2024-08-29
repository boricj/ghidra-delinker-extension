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
package ghidra.app.analyzers.relocations.patterns;

public class OperandMatch {
	private final int operandIndex;
	private final int offset;
	private final int size;
	private final long bitmask;
	private final long value;

	public OperandMatch(int operandIndex, int offset, int size, long bitmask, long value) {
		this.operandIndex = operandIndex;
		this.offset = offset;
		this.size = size;
		this.bitmask = bitmask;
		this.value = value;
	}

	public int getOperandIndex() {
		return operandIndex;
	}

	public int getOffset() {
		return offset;
	}

	public int getSize() {
		return size;
	}

	public long getBitmask() {
		return bitmask;
	}

	public long getValue() {
		return value;
	}
}
