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
package ghidra.app.util.exporter.omf;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.util.Iterator;
import java.util.List;

import org.junit.Test;

import ghidra.DelinkerIntegrationTest;
import ghidra.app.util.exporter.OmfRelocatableObjectExporter;
import ghidra.program.model.address.AddressSetView;
import net.boricj.bft.omf.OmfFile;
import net.boricj.bft.omf.OmfRecord;
import net.boricj.bft.omf.OmfSegmentData;
import net.boricj.bft.omf.records.OmfRecordFixupp;
import net.boricj.bft.omf.records.OmfRecordLidata;
import net.boricj.bft.omf.records.OmfRecordLedata;
import net.boricj.bft.omf.records.OmfRecordPubdef;
import net.boricj.bft.omf.records.OmfRecordPubdef.PublicSymbol;
import net.boricj.bft.omf.records.OmfRecordSegdef;

public class OMF_I386_huge_relocation_table_Test extends DelinkerIntegrationTest {
	private static final int MAX_FIXUP_ENTRIES_PER_RECORD = 254;

	@Override
	protected String getProgramName() {
		return "src/test/resources/omf/huge-relocation-table.obj.gzf";
	}

	@Test
	public void testExport_huge_relocation_table_obj() throws Exception {
		AddressSetView set = getAddressSetOfMemoryBlocks(getProgram(),
			List.of("_DATA", "$$BSYMS", "$$BTYPES", "$$BNAMES"));

		File exportedFile = exportObjectFile(set, new OmfRelocatableObjectExporter(), null);
		OmfFile exported = parseOmf(exportedFile);
		OmfSegmentData dataSegment = segmentData(exported, "_DATA");
		int dataLength = dataSegment.getBytes().length;
		assertTrue("Expected non-empty _DATA payload", dataLength > 0);
		assertEquals("Expected _DATA payload to be dword-addressable", 0, dataLength % 4);

		List<PublicSymbol> symbols = recordsOfType(exported, OmfRecordPubdef.class).stream()
				.filter(pubdef -> pubdef.getSegment() != null)
				.filter(pubdef -> "_DATA".equals(pubdef.getSegment().getSegmentName()))
				.flatMap(pubdef -> pubdef.getSymbols().stream())
				.toList();
		assertEquals("Expected one public symbol per dword", dataLength / 4, symbols.size());
		for (int i = 0; i < symbols.size(); i++) {
			PublicSymbol symbol = symbols.get(i);
			assertEquals("Unexpected _DATA symbol name at index " + i,
				String.format("_sym_%08x", i), symbol.name());
			assertEquals("Unexpected _DATA symbol offset at index " + i,
				(long) i * 4L, symbol.offset());
		}

		assertInterleavedDataFixupInvariants(exported, "_DATA", dataLength);
	}

	private static OmfFile parseOmf(File file) throws Exception {
		return new OmfFile.Parser(new FileInputStream(file)).parse();
	}

	private static OmfSegmentData segmentData(OmfFile file, String segmentName) {
		return OmfSegmentData.parse(file, findSegmentByName(file, segmentName));
	}

	private static void assertInterleavedDataFixupInvariants(
			OmfFile file,
			String segmentName,
			int expectedSegmentLength) {
		OmfRecordSegdef segment = findSegmentByName(file, segmentName);
		boolean activeDataChunkBelongsToTarget = false;
		int activeChunkLength = 0;
		int expectedRelativeFixupOffset = 0;
		int totalFixupCount = 0;

		Iterator<OmfRecord> it = file.getElements().iterator();
		while (it.hasNext()) {
			OmfRecord record = it.next();

			if (record instanceof OmfRecordLedata ledata) {
				if (activeDataChunkBelongsToTarget) {
					assertEquals("Expected fixups to cover active _DATA LEDATA chunk",
						activeChunkLength, expectedRelativeFixupOffset);
				}
				activeDataChunkBelongsToTarget = (ledata.getSegment() == segment);
				activeChunkLength = activeDataChunkBelongsToTarget ? ledata.getData().length : 0;
				expectedRelativeFixupOffset = 0;
				continue;
			}

			if (record instanceof OmfRecordLidata lidata) {
				if (activeDataChunkBelongsToTarget) {
					assertEquals("Expected fixups to cover active _DATA LIDATA chunk",
						activeChunkLength, expectedRelativeFixupOffset);
				}
				if (lidata.getSegment() == segment) {
					fail(
						"Unexpected LIDATA chunk in _DATA; test expects LEDATA/FIXUPP interleaving");
				}
				activeDataChunkBelongsToTarget = false;
				activeChunkLength = 0;
				expectedRelativeFixupOffset = 0;
				continue;
			}

			if (record instanceof OmfRecordFixupp fixupp) {
				if (!activeDataChunkBelongsToTarget) {
					continue;
				}
				assertTrue("FIXUPP record exceeds per-record fixup cap",
					fixupp.getFixupEntries().size() <= MAX_FIXUP_ENTRIES_PER_RECORD);
				for (OmfRecordFixupp.FixupEntry entry : fixupp.getFixupEntries()) {
					assertEquals("Unexpected relative fixup offset inside active _DATA chunk",
						expectedRelativeFixupOffset, entry.getDataRecordOffset());
					expectedRelativeFixupOffset += 4;
					totalFixupCount++;
				}
				continue;
			}

			if (activeDataChunkBelongsToTarget) {
				assertEquals("Expected fixups to cover active _DATA data chunk",
					activeChunkLength, expectedRelativeFixupOffset);
			}
			activeDataChunkBelongsToTarget = false;
			activeChunkLength = 0;
			expectedRelativeFixupOffset = 0;
		}

		if (activeDataChunkBelongsToTarget) {
			assertEquals("Expected fixups to cover final _DATA data chunk",
				activeChunkLength, expectedRelativeFixupOffset);
		}

		assertEquals("Expected one fixup per dword in _DATA", expectedSegmentLength / 4,
			totalFixupCount);
	}

	private static <T extends OmfRecord> List<T> recordsOfType(OmfFile file, Class<T> clazz) {
		return file.getElements().stream().filter(clazz::isInstance).map(clazz::cast).toList();
	}

}
