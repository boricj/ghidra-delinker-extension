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

import java.util.List;
import java.util.Objects;

/**
 * Homogeneous set of relocation entries sharing one relocation type and encoding shape.
 */
public class RelocationGang {
	private final RelocationTypeTag relocationType;
	private final int width;
	private final long bitmask;
	private final List<RelocationEntry> entries;

	public RelocationGang(RelocationTypeTag relocationType, int width, long bitmask,
			List<RelocationEntry> entries) {
		this.relocationType = Objects.requireNonNull(relocationType);
		this.width = width;
		this.bitmask = bitmask;
		this.entries = List.copyOf(entries);
	}

	public RelocationTypeTag getRelocationType() {
		return relocationType;
	}

	public int getWidth() {
		return width;
	}

	public long getBitmask() {
		return bitmask;
	}

	public List<RelocationEntry> getEntries() {
		return entries;
	}
}
