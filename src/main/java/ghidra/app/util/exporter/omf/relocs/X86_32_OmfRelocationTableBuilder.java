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

import static ghidra.app.util.ProgramUtil.getOffsetWithinAddressSet;
import static ghidra.app.util.ProgramUtil.patchBytes;
import static ghidra.app.util.exporter.omf.relocs.OmfRelocationTableBuilder.logUnknownRelocation;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Language;
import ghidra.program.model.relocobj.Relocation;
import ghidra.program.model.relocobj.RelocationAbsolute;
import ghidra.program.model.relocobj.RelocationRelativePC;
import ghidra.util.DataConverter;
import ghidra.util.LittleEndianDataConverter;
import net.boricj.bft.omf.records.OmfRecordFixupp.DisplacementType;
import net.boricj.bft.omf.records.OmfRecordFixupp.FixupEntry;
import net.boricj.bft.omf.records.OmfRecordFixupp.FrameMethod;
import net.boricj.bft.omf.records.OmfRecordFixupp.TargetMethod;
import net.boricj.bft.omf.records.OmfRecordSegdef;

/**
 * Builds OMF FIXUPP records for x86 32-bit relocations.
 */
public class X86_32_OmfRelocationTableBuilder implements OmfRelocationTableBuilder {
	@Override
	public List<FixupAtOffset> build(OmfRecordSegdef segment,
			java.util.Map<Address, Integer> addressToExtdefIndex, byte[] bytes,
			AddressSetView addressSet, List<Relocation> relocations,
			List<SegmentMapping> segmentMappings, MessageLog log) {
		List<FixupAtOffset> fixups = new ArrayList<>();

		for (Relocation relocation : relocations) {
			if (relocation instanceof RelocationAbsolute) {
				process(fixups, segment, addressToExtdefIndex, segmentMappings, bytes, addressSet,
					(RelocationAbsolute) relocation, log);
			}
			else if (relocation instanceof RelocationRelativePC) {
				process(fixups, segment, addressToExtdefIndex, segmentMappings, bytes, addressSet,
					(RelocationRelativePC) relocation, log);
			}
			else {
				logUnknownRelocation(segment, relocation, log);
			}
		}

		return fixups;
	}

	private void process(List<FixupAtOffset> fixups, OmfRecordSegdef segment,
			java.util.Map<Address, Integer> addressToExtdefIndex,
			List<SegmentMapping> segmentMappings, byte[] bytes, AddressSetView addressSet,
			RelocationAbsolute relocation, MessageLog log) {
		DataConverter dc = LittleEndianDataConverter.INSTANCE;
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long value = relocation.getAddend();

		// Only support 32-bit absolute relocations
		if (width != 4 || bitmask != 0xffffffffL) {
			logUnknownRelocation(segment, relocation, log);
			return;
		}

		// Emit fixup entry
		// Location type: Offset32 (9) = 32-bit offset
		int locationType = 9;
		boolean segmentRelative = true;

		// Frame method: TARGET (5) = frame is target's segment
		FrameMethod frameMethod = FrameMethod.TARGET;
		int frameIndex = 0; // Not used with TARGET frame method

		// Determine target method and index
		TargetMethod targetMethod;
		int targetIndex;
		Address targetAddress = relocation.getTarget();

		// First check if target is an external symbol
		Integer extdefIndex = addressToExtdefIndex.get(targetAddress);
		if (extdefIndex != null) {
			// External symbol
			targetMethod = TargetMethod.EXTDEF_INDEX;
			targetIndex = extdefIndex; // Already 1-based
		}
		else {
			// Check if target is in a known segment.
			SegmentMapping targetSegment = findSegment(targetAddress, segmentMappings);
			if (targetSegment != null) {
				// Segment reference
				targetMethod = TargetMethod.SEGDEF_INDEX;
				targetIndex = targetSegment.segdefIndex; // Already 1-based
				value += getOffsetWithinAddressSet(targetSegment.addressSet, targetAddress);
			}
			else {
				// Cannot resolve target
				log.appendMsg(segment.getSegmentName(),
					"Cannot resolve relocation target: " + targetAddress);
				return;
			}
		}

		// Patch bytes with computed relocation value.
		patchBytes(bytes, addressSet, dc, relocation, value);

		int dataOffset = (int) getOffsetWithinAddressSet(addressSet, relocation.getAddress());

		fixups.add(new FixupAtOffset(dataOffset,
			new FixupEntry(0, locationType, segmentRelative,
				frameMethod, targetMethod, frameIndex, targetIndex, DisplacementType.D32)));
	}

	private void process(List<FixupAtOffset> fixups, OmfRecordSegdef segment,
			java.util.Map<Address, Integer> addressToExtdefIndex,
			List<SegmentMapping> segmentMappings, byte[] bytes, AddressSetView addressSet,
			RelocationRelativePC relocation, MessageLog log) {
		DataConverter dc = LittleEndianDataConverter.INSTANCE;
		int width = relocation.getWidth();
		long bitmask = relocation.getBitmask();
		long value = relocation.getAddend() + width; // Adjust for size

		// Only support 32-bit PC-relative relocations
		if (width != 4 || bitmask != 0xffffffffL) {
			logUnknownRelocation(segment, relocation, log);
			return;
		}

		// Emit fixup entry
		// Location type: Offset32 (9) = 32-bit offset
		int locationType = 9;
		boolean segmentRelative = false;

		// Frame method: TARGET (5) = frame is target's segment
		FrameMethod frameMethod = FrameMethod.TARGET;
		int frameIndex = 0; // Not used with TARGET frame method

		// Determine target method and index
		TargetMethod targetMethod;
		int targetIndex;
		Address targetAddress = relocation.getTarget();

		// First check if target is an external symbol
		Integer extdefIndex = addressToExtdefIndex.get(targetAddress);
		if (extdefIndex != null) {
			// External symbol
			targetMethod = TargetMethod.EXTDEF_INDEX;
			targetIndex = extdefIndex;
		}
		else {
			// Check if target is in a known segment.
			SegmentMapping targetSegment = findSegment(targetAddress, segmentMappings);
			if (targetSegment != null) {
				// Segment reference
				targetMethod = TargetMethod.SEGDEF_INDEX;
				targetIndex = targetSegment.segdefIndex;
				value += getOffsetWithinAddressSet(targetSegment.addressSet, targetAddress);
			}
			else {
				// Cannot resolve target
				log.appendMsg(segment.getSegmentName(),
					"Cannot resolve relocation target: " + targetAddress);
				return;
			}
		}

		// Patch bytes with computed relocation value.
		patchBytes(bytes, addressSet, dc, relocation, value);

		int dataOffset = (int) getOffsetWithinAddressSet(addressSet, relocation.getAddress());

		fixups.add(new FixupAtOffset(dataOffset,
			new FixupEntry(0, locationType, segmentRelative,
				frameMethod, targetMethod, frameIndex, targetIndex, DisplacementType.D32)));
	}

	private SegmentMapping findSegment(Address address, List<SegmentMapping> segmentMappings) {
		for (SegmentMapping mapping : segmentMappings) {
			if (mapping.addressSet.contains(address)) {
				return mapping;
			}
		}
		return null;
	}

	@Override
	public boolean canBuild(Language language) {
		String processor = language.getProcessor().toString();
		int pointerSize = language.getDefaultSpace().getPointerSize();

		return processor.equals("x86") && pointerSize == 4;
	}
}
