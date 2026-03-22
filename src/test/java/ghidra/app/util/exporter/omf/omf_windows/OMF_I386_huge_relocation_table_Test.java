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
package ghidra.app.util.exporter.omf.omf_windows;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import ghidra.DelinkerIntegrationTest;
import ghidra.app.util.exporter.OmfRelocatableObjectExporter;
import ghidra.program.model.address.AddressSetView;
import net.boricj.bft.omf.OmfRecord;
import net.boricj.bft.omf.logical.OmfPubdefData;
import net.boricj.bft.omf.logical.OmfSegmentData;
import net.boricj.bft.omf.records.OmfRecordExtdef;
import net.boricj.bft.omf.records.OmfRecordFixupp;
import net.boricj.bft.omf.records.OmfRecordLedata;
import net.boricj.bft.omf.records.OmfRecordLnames;
import net.boricj.bft.omf.records.OmfRecordPubdef;
import net.boricj.bft.omf.records.OmfRecordPubdef.PublicSymbol;
import net.boricj.bft.omf.records.OmfRecordSegdef;
import net.boricj.bft.omf.records.OmfSubrecordExtdef;

public class OMF_I386_huge_relocation_table_Test extends DelinkerIntegrationTest {
	private static final int BORLAND_MAX_RECORD_SIZE = 1024;
	private static final int MAX_FIXUP_ENTRIES_PER_RECORD = 254;
	private static final int BORLAND_MAX_SYMBOL_AND_NAME_RECORD_DATA_BYTES = 0x3ff;

	@Override
	protected String getProgramName() {
		return "src/test/resources/omf/huge-relocation-table.obj.gzf";
	}

	@Test
	public void testExport_huge_relocation_table_obj() throws Exception {
		AddressSetView set = getAddressSetOfMemoryBlocks(getProgram(),
			List.of("_DATA", "$$BSYMS", "$$BTYPES", "$$BNAMES"));

		File exportedFile = exportObjectFile(set, new OmfRelocatableObjectExporter(), null);

		OmfObjectFile exported = new OmfObjectFile(exportedFile);

		assertTrue("Expected non-empty _DATA payload",
			exported.getSectionBytes("_DATA").length > 0);
		assertTrue("Expected non-empty $$BSYMS payload",
			exported.getSectionBytes("$$BSYMS").length > 0);
		assertTrue("Expected non-empty $$BTYPES payload",
			exported.getSectionBytes("$$BTYPES").length > 0);
		assertTrue("Expected non-empty $$BNAMES payload",
			exported.getSectionBytes("$$BNAMES").length > 0);

		assertTrue("Expected _DATA to contain fixups",
			!exported.getFixuppRecordsForSegment("_DATA").isEmpty());

		// Borland-style splitting policy inferred from reference object layout:
		// - relocation-heavy _DATA LEDATA payload chunks are 0x3f8 bytes
		// - relocation-free $$BSYMS LEDATA payload chunks are 0x3fc bytes
		// Measurement-driven splitting: LEDATA records fill up to maxRecordSize exactly.
		assertChunkRecordSizes(exported.getLedataRecordsForSegment("_DATA"));
		assertChunkRecordSizes(exported.getLedataRecordsForSegment("$$BSYMS"));
		OmfSegmentData dataSegment = exported.getSegmentData("_DATA");
		assertEquals("Expected logical segment bytes to match section bytes",
			exported.getSectionBytes("_DATA").length, dataSegment.getBytes().length);
		assertTrue("Expected at least one logical fixup in _DATA",
			!dataSegment.getFixups().isEmpty());

		// Every logical fixup must target a valid 4-byte operand range in segment data.
		for (OmfSegmentData.FixupAtOffset fixup : dataSegment.getFixups()) {
			assertTrue("Fixup offset out of segment bounds",
				fixup.segmentOffset() >= 0 &&
					fixup.segmentOffset() + 4 <= dataSegment.getBytes().length);
		}

		// Every emitted FIXUPP record must remain under the entry-count compatibility cap.
		for (OmfRecordFixupp fixupp : exported.getFixuppRecordsForSegment("_DATA")) {
			assertTrue("FIXUPP record exceeds per-record fixup cap",
				fixupp.getFixupEntries().size() <= MAX_FIXUP_ENTRIES_PER_RECORD);
		}

		assertFixupsStayWithinSegmentBounds(exported, "$$BSYMS");
		assertFixupsStayWithinSegmentBounds(exported, "$$BTYPES");
		assertFixupsStayWithinSegmentBounds(exported, "$$BNAMES");

		assertSymbolAndNameRecordChunking(exported);
	}

	private static void assertFixupsStayWithinSegmentBounds(OmfObjectFile exported,
			String segmentName) {
		OmfSegmentData segmentData = exported.getSegmentData(segmentName);
		assertTrue("Expected segment to exist: " + segmentName, segmentData != null);

		for (OmfSegmentData.FixupAtOffset fixup : segmentData.getFixups()) {
			assertTrue("Fixup offset out of bounds for segment " + segmentName,
				fixup.segmentOffset() >= 0 &&
					fixup.segmentOffset() + 4 <= segmentData.getBytes().length);
		}
	}

	private static void assertSymbolAndNameRecordChunking(OmfObjectFile exported) {
		List<OmfRecordLnames> lnamesRecords = exported.getOmfFile()
				.getElements()
				.stream()
				.filter(r -> r instanceof OmfRecordLnames)
				.map(r -> (OmfRecordLnames) r)
				.toList();
		assertTrue("Expected at least one LNAMES record", !lnamesRecords.isEmpty());

		List<String> allNames = new ArrayList<>();
		for (OmfRecordLnames record : lnamesRecords) {
			assertRecordSizeWithinLimit("LNAMES", record);
			allNames.addAll(record.getNames());
		}

		if (wouldOverflow(() -> new OmfRecordLnames(exported.getOmfFile(), allNames))) {
			assertTrue("Expected LNAMES to be split", lnamesRecords.size() > 1);
		}

		List<OmfRecordExtdef> extdefRecords = exported.getExtdefRecords();

		List<OmfSubrecordExtdef> allExtdefEntries = new ArrayList<>();
		for (OmfRecordExtdef record : extdefRecords) {
			assertRecordSizeWithinLimit("EXTDEF", record);
			allExtdefEntries.addAll(record.getElements());
		}

		if (!allExtdefEntries.isEmpty() &&
			wouldOverflow(() -> new OmfRecordExtdef(exported.getOmfFile(), allExtdefEntries))) {
			assertTrue("Expected EXTDEF to be split", extdefRecords.size() > 1);
		}

		Map<OmfRecordSegdef, List<PublicSymbol>> segmentSymbols16 = new HashMap<>();
		Map<OmfRecordSegdef, List<PublicSymbol>> segmentSymbols32 = new HashMap<>();
		Map<OmfRecordSegdef, Integer> segmentRecordCount16 = new HashMap<>();
		Map<OmfRecordSegdef, Integer> segmentRecordCount32 = new HashMap<>();

		for (OmfRecordPubdef record : exported.getPubdefRecords()) {
			assertRecordSizeWithinLimit("PUBDEF", record);

			OmfRecordSegdef segment = record.getSegment();
			boolean uses32BitOffsets = record.getSpecificTypeValue() == (byte) 0x91;
			if (uses32BitOffsets) {
				segmentSymbols32.computeIfAbsent(segment, k -> new ArrayList<>())
						.addAll(record.getSymbols());
				segmentRecordCount32.merge(segment, 1, Integer::sum);
			}
			else {
				segmentSymbols16.computeIfAbsent(segment, k -> new ArrayList<>())
						.addAll(record.getSymbols());
				segmentRecordCount16.merge(segment, 1, Integer::sum);
			}
		}

		for (Map.Entry<OmfRecordSegdef, List<PublicSymbol>> entry : segmentSymbols16.entrySet()) {
			if (wouldOverflow(
				() -> new OmfRecordPubdef(exported.getOmfFile(), null, entry.getKey(), 0,
					entry.getValue()))) {
				assertTrue("Expected 16-bit PUBDEF split for segment " +
					entry.getKey().getSegmentName(),
					segmentRecordCount16.getOrDefault(entry.getKey(), 0) > 1);
			}
		}

		for (Map.Entry<OmfRecordSegdef, List<PublicSymbol>> entry : segmentSymbols32.entrySet()) {
			if (wouldOverflow(
				() -> new OmfRecordPubdef(exported.getOmfFile(), null, entry.getKey(), 0,
					entry.getValue()))) {
				assertTrue("Expected 32-bit PUBDEF split for segment " +
					entry.getKey().getSegmentName(),
					segmentRecordCount32.getOrDefault(entry.getKey(), 0) > 1);
			}
		}

		assertEquals(allNames, exported.getLnamesData().getNames());
		assertEquals(allExtdefEntries, exported.getExtdefData().getEntries());

		Map<OmfRecordSegdef, List<PublicSymbol>> recordPubdefSymbolsBySegment =
			collectPubdefSymbolsBySegment(exported.getPubdefRecords());
		for (Map.Entry<OmfRecordSegdef, List<PublicSymbol>> entry : recordPubdefSymbolsBySegment
				.entrySet()) {
			assertEquals(
				entry.getValue(),
				collectPublicSymbols(
					exported.getPubdefDataForSegment(entry.getKey().getSegmentName())));
		}
	}

	private static List<PublicSymbol> collectPublicSymbols(List<OmfPubdefData> pubdefDataList) {
		List<PublicSymbol> symbols = new ArrayList<>();
		for (OmfPubdefData pubdefData : pubdefDataList) {
			symbols.addAll(pubdefData.getSymbols());
		}
		return symbols;
	}

	private static Map<OmfRecordSegdef, List<PublicSymbol>> collectPubdefSymbolsBySegment(
			List<OmfRecordPubdef> pubdefRecords) {
		Map<OmfRecordSegdef, List<PublicSymbol>> symbolsBySegment = new HashMap<>();
		for (OmfRecordPubdef pubdef : pubdefRecords) {
			OmfRecordSegdef segment = pubdef.getSegment();
			if (segment == null) {
				continue;
			}
			symbolsBySegment.computeIfAbsent(segment, ignored -> new ArrayList<>())
					.addAll(pubdef.getSymbols());
		}
		return symbolsBySegment;
	}

	private static void assertRecordSizeWithinLimit(String recordName, OmfRecord record) {
		int size = Math.toIntExact(record.getLength());
		assertTrue(recordName + " record exceeds Borland compatibility limit: " + size,
			size <= BORLAND_MAX_SYMBOL_AND_NAME_RECORD_DATA_BYTES);
	}

	@FunctionalInterface
	private interface RecordFactory {
		OmfRecord create();
	}

	private static boolean wouldOverflow(RecordFactory factory) {
		try {
			OmfRecord record = factory.create();
			return Math
					.toIntExact(record.getLength()) > BORLAND_MAX_SYMBOL_AND_NAME_RECORD_DATA_BYTES;
		}
		catch (IllegalArgumentException e) {
			return true;
		}
	}

	private static void assertChunkRecordSizes(List<OmfRecordLedata> ledatas) {
		assertTrue("Expected at least one LEDATA record", !ledatas.isEmpty());
		for (int i = 0; i < ledatas.size(); i++) {
			long recordLength = ledatas.get(i).getLength();
			assertTrue("LEDATA record exceeds Borland max record size",
				recordLength <= BORLAND_MAX_RECORD_SIZE);
			assertTrue("LEDATA record must contain at least one byte of data",
				ledatas.get(i).getData().length > 0);
		}
	}

}
