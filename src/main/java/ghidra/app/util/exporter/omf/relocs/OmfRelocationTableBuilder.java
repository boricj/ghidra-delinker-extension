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
package ghidra.app.util.exporter.omf.relocs;

import java.util.List;
import java.util.Map;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Language;
import ghidra.program.model.relocobj.Relocation;
import ghidra.util.classfinder.ExtensionPoint;
import net.boricj.bft.omf.records.OmfRecordFixupp.FixupEntry;
import net.boricj.bft.omf.records.OmfRecordSegdef;

/**
 * Extension point for building OMF FIXUPP records from Ghidra relocations.
 */
public interface OmfRelocationTableBuilder extends ExtensionPoint {
	/**
	 * One FIXUPP entry anchored at an absolute segment byte offset.
	 */
	public static record FixupAtOffset(int segmentOffset, FixupEntry entry) {
		public FixupAtOffset {
			if (segmentOffset < 0) {
				throw new IllegalArgumentException(
					"segmentOffset must be non-negative: " + segmentOffset);
			}
		}
	}

	/**
	 * Maps an address range to its 1-based SEGDEF index for intra-segment relocations.
	 */
	public static class SegmentMapping {
		public final AddressSetView addressSet;
		public final int segdefIndex;

		public SegmentMapping(AddressSetView addressSet, int segdefIndex) {
			this.addressSet = addressSet;
			this.segdefIndex = segdefIndex;
		}
	}

	/**
	 * Builds FIXUPP entries for a segment.
	 *
	 * @param segment the target segment
	 * @param addressToExtdefIndex map from target address to EXTDEF index (1-based)
	 * @param bytes the segment data bytes
	 * @param addressSet the address set covered by this segment
	 * @param relocations the relocations to process
	 * @param segmentMappings list of segment address ranges and their SEGDEF indices for intra-segment relocations
	 * @param log the message log for reporting issues
	 * @return list of FIXUPP semantics paired with their absolute segment offsets
	 */
	List<FixupAtOffset> build(OmfRecordSegdef segment, Map<Address, Integer> addressToExtdefIndex,
			byte[] bytes, AddressSetView addressSet, List<Relocation> relocations,
			List<SegmentMapping> segmentMappings, MessageLog log);

	/**
	 * Checks if this builder can handle the given language.
	 *
	 * @param language the program language
	 * @return true if this builder supports the language
	 */
	boolean canBuild(Language language);

	/**
	 * Helper method to log unknown relocations.
	 *
	 * @param segment the segment
	 * @param relocation the relocation
	 * @param log the message log
	 */
	static void logUnknownRelocation(OmfRecordSegdef segment, Relocation relocation,
			MessageLog log) {
		String name = relocation.getClass().getSimpleName();
		String msg = String.format("Unknown relocation %s width %d bitmask %d at %s", name,
			relocation.getWidth(), relocation.getBitmask(), relocation.getAddress());
		log.appendMsg(segment.getSegmentName(), msg);
	}
}
