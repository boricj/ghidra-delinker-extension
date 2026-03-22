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
package ghidra.app.util.exporter.asciitable.omf_windows;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.Test;

import ghidra.DelinkerIntegrationTest;
import ghidra.app.util.ProgramUtil;
import ghidra.app.util.SymbolInformation;
import ghidra.app.util.SymbolPreference;
import ghidra.app.util.exporter.OmfRelocatableObjectExporter;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import net.boricj.bft.omf.logical.OmfPubdefData;
import net.boricj.bft.omf.logical.OmfSegmentData;

public class OMF_I386_ascii_table_Test extends DelinkerIntegrationTest {
	private static final File referenceFile =
		new File("src/test/resources/ascii-table/reference/omf_windows/i386/ascii-table.obj");

	@Override
	protected String getProgramName() {
		return "src/test/resources/ascii-table/reference/omf_windows/i386/ascii-table.exe.gzf";
	}

	@Test
	public void testExport_ascii_table_obj() throws Exception {
		AddressFactory af = getProgram().getAddressFactory();

		// Export _TEXT and _DATA segments
		// _TEXT: 00401200-0040141d (0x21E bytes)
		// _DATA: 0040a0a4-0040a0fb (0x58 bytes)
		AddressSetView set = af.getAddressSet(af.getAddress("00401200"), af.getAddress("0040141d"))
				.union(af.getAddressSet(af.getAddress("0040a0a4"), af.getAddress("0040a0fb")));

		File exportedFile = exportObjectFile(set, new OmfRelocatableObjectExporter(), null);

		OmfObjectFile reference = new OmfObjectFile(referenceFile);
		OmfObjectFile exported = new OmfObjectFile(exportedFile);

		// Compare segment bytes (note: exported uses actual Ghidra segment names .text, .data)
		reference.compareSectionBytes("_TEXT", exported, ".text");
		reference.compareSectionBytes("_DATA", exported, ".data");

		// Verify public symbols
		exported.hasPublicSymbol("_NUM_ASCII_PROPERTIES", ".data", 0x0000);
		exported.hasPublicSymbol("_s_ascii_properties", ".data", 0x0004);
		exported.hasPublicSymbol("_COLUMNS", ".data", 0x0054);
		exported.hasPublicSymbol("_print_number", ".text", 0x0000);
		exported.hasPublicSymbol("_print_ascii_entry", ".text", 0x007D);
		exported.hasPublicSymbol("_main", ".text", 0x018E);

		// Verify fixup placement remains equivalent to the reference object.
		reference.compareFixupOffsets("_TEXT", exported, ".text");
		reference.compareFixupOffsets("_DATA", exported, ".data");

		List<String> expectedExtdefNames = new ArrayList<>(ProgramUtil
				.getExternalSymbols(getProgram(), set, SymbolPreference.MSVC)
				.values()
				.stream()
				.map(SymbolInformation::getName)
				.toList());
		List<String> actualExtdefNames = new ArrayList<>(exported.getExtdefData()
				.getEntries()
				.stream()
				.map(entry -> entry.name())
				.toList());
		Collections.sort(expectedExtdefNames);
		Collections.sort(actualExtdefNames);
		assertEquals(expectedExtdefNames, actualExtdefNames);
		assertTrue("Expected .text to contain EXTDEF-indexed fixups",
			exported.assertTargetExtdefIndicesMatchLogicalOrder(".text") > 0);
		exported.assertTargetExtdefIndicesMatchLogicalOrder(".data");

		assertEquals(
			List.of("_print_number", "_print_ascii_entry", "_main"),
			collectPublicSymbolNames(exported.getPubdefDataForSegment(".text")));
		assertEquals(
			List.of("_NUM_ASCII_PROPERTIES", "_s_ascii_properties", "_COLUMNS"),
			collectPublicSymbolNames(exported.getPubdefDataForSegment(".data")));

		// Segment-layer assertions for enhanced diagnostics and round-trip validation.
		validateSegmentData(exported, ".text");
		validateSegmentData(exported, ".data");
	}

	@Test
	public void testExport_ascii_table_sparse_text_selection_coalesces_into_one_segment()
			throws Exception {
		AddressFactory af = getProgram().getAddressFactory();
		AddressSetView sparseTextSet =
			af.getAddressSet(af.getAddress("00401200"), af.getAddress("0040120f"))
					.union(af.getAddressSet(af.getAddress("00401220"), af.getAddress("0040122f")));

		File exportedFile = exportObjectFile(sparseTextSet, new OmfRelocatableObjectExporter(),
			null);
		OmfObjectFile exported = new OmfObjectFile(exportedFile);
		byte[] exportedBytes = exported.getSectionBytes(".text");
		assertEquals(0x20, exportedBytes.length);

		OmfSegmentData segment = exported.getSegmentData(".text");
		assertTrue("Expected sparse .text selection to export as a single segment",
			segment != null);
		assertEquals(0x20, segment.getBytes().length);
		assertArrayEquals(exportedBytes, segment.getBytes());

		for (OmfSegmentData.FixupAtOffset fixup : segment.getFixups()) {
			assertTrue(
				"Expected sparse-selection fixup offsets to be rebased into the coalesced segment",
				fixup.segmentOffset() >= 0 && fixup.segmentOffset() + 4 <= 0x20);
		}
	}

	private static List<String> collectPublicSymbolNames(List<OmfPubdefData> pubdefDataList) {
		return pubdefDataList.stream()
				.flatMap(pubdefData -> pubdefData.getSymbols().stream())
				.map(symbol -> symbol.name())
				.toList();
	}

	private void validateSegmentData(OmfObjectFile exportedFile, String segmentName)
			throws IOException {
		OmfSegmentData segment = exportedFile.getSegmentData(segmentName);
		assertTrue("Segment " + segmentName + " should be present", segment != null);

		// Verify logical segment bytes match exported section.
		byte[] sectionBytes = exportedFile.getSectionBytes(segmentName);
		assertTrue("Segment bytes count mismatch for " + segmentName,
			segment.getBytes().length == sectionBytes.length);

		// Verify all fixups are within segment bounds (4-byte aligned operand).
		for (OmfSegmentData.FixupAtOffset fixup : segment.getFixups()) {
			assertTrue(
				"Fixup offset out of bounds for " + segmentName + ": offset " +
					fixup.segmentOffset() + " in segment of size " + segment.getBytes().length,
				fixup.segmentOffset() >= 0 &&
					fixup.segmentOffset() + 4 <= segment.getBytes().length);
		}
	}
}
