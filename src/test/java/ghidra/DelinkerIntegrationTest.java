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
package ghidra;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Before;

import db.DBHandle;
import generic.jar.ResourceFile;
import ghidra.app.analyzers.RelocationTableSynthesizerAnalyzer;
import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.bin.format.coff.CoffSymbolSectionNumber;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.GModule;
import ghidra.framework.data.OpenMode;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.db.PrivateDatabase;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractProgramBasedTest;
import ghidra.test.TestProgramManager;
import ghidra.util.NamingUtilities;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;
import net.boricj.bft.coff.CoffFile;
import net.boricj.bft.coff.CoffSection;
import net.boricj.bft.coff.constants.CoffRelocationType;
import net.boricj.bft.coff.sections.CoffBytes;
import net.boricj.bft.elf.ElfFile;
import net.boricj.bft.elf.ElfSection;
import net.boricj.bft.elf.constants.ElfRelocationType;
import net.boricj.bft.elf.sections.ElfProgBits;
import net.boricj.bft.elf.sections.ElfRelTable;
import net.boricj.bft.elf.sections.ElfRelaTable;
import net.boricj.bft.elf.sections.ElfSymbolTable;
import net.boricj.bft.omf.OmfFile;
import net.boricj.bft.omf.OmfRecord;
import net.boricj.bft.omf.logical.OmfExtdefData;
import net.boricj.bft.omf.logical.OmfLnamesData;
import net.boricj.bft.omf.logical.OmfPubdefData;
import net.boricj.bft.omf.logical.OmfSegmentData;
import net.boricj.bft.omf.records.OmfRecordExtdef;
import net.boricj.bft.omf.records.OmfRecordFixupp;
import net.boricj.bft.omf.records.OmfRecordLedata;
import net.boricj.bft.omf.records.OmfRecordPubdef;
import net.boricj.bft.omf.records.OmfRecordSegdef;
import net.boricj.bft.omf.records.OmfSubrecordExtdef;
import utility.application.ApplicationLayout;

public abstract class DelinkerIntegrationTest extends AbstractProgramBasedTest {
	private static DBHandle dbHandle = null;
	private static Program program = null;
	private static boolean initialized = false;

	public interface ObjectFile {
		public byte[] getSectionBytes(String name) throws IOException;

		public default void compareSectionBytes(String referenceSectionName,
				ObjectFile exportedFile, String exportedSectionName) throws Exception {
			compareSectionBytes(referenceSectionName, exportedFile, exportedSectionName,
				Collections.emptyMap());
		}

		public default void compareSectionBytes(String referenceSectionName,
				ObjectFile exportedFile, String exportedSectionName, Map<Integer, byte[]> patches)
				throws Exception {
			byte[] expectedBytes = getSectionBytes(referenceSectionName);
			byte[] actualBytes = exportedFile.getSectionBytes(exportedSectionName);

			for (Map.Entry<Integer, byte[]> entry : patches.entrySet()) {
				byte[] patch = entry.getValue();
				System.arraycopy(patch, 0, expectedBytes, entry.getKey(), patch.length);
			}

			assertArrayEquals(expectedBytes, actualBytes);
		}
	}

	public class ElfObjectFile implements ObjectFile {
		private final ElfFile elf;

		public ElfObjectFile(File file) throws IOException {
			this.elf = new ElfFile.Parser(new FileInputStream(file)).parse();
		}

		public ElfObjectFile(File file, boolean ignoreSectionErrors) throws IOException {
			this.elf = new ElfFile.Parser(new FileInputStream(file))
					.setIgnoreSectionErrors(ignoreSectionErrors)
					.parse();
		}

		@Override
		public byte[] getSectionBytes(String name) throws IOException {
			return ((ElfProgBits) getSection(name)).getBytes();
		}

		public void hasSymbolAtAddress(String symbolTable, String symbolName, String sectionName,
				int offset) {
			ElfSymbolTable symtab = getSymbolTable(symbolTable);

			assertTrue(symtab.stream()
					.filter(symbol -> symbol.getName().equals(symbolName))
					.anyMatch(symbol -> {
						ElfSection section =
							elf.getSections().get(symbol.getIndex());
						return section.getName().equals(sectionName) &&
							symbol.getValue() == offset;
					}));
		}

		public void hasUndefinedSymbol(String symbolTable, String symbolName) {
			ElfSymbolTable symtab = getSymbolTable(symbolTable);

			assertTrue(symtab.stream()
					.filter(symbol -> symbol.getName().equals(symbolName))
					.anyMatch(symbol -> symbol.getIndex() == ElfSection.SHN_UNDEF));
		}

		public void hasRelocationAtAddress(String relTable, long offset, ElfRelocationType type,
				String symbolName) {
			ElfRelTable rel = getRelTable(relTable);

			assertTrue(rel.stream()
					.filter(r -> r.getOffset() == offset)
					.anyMatch(
						r -> r.getType() == type && r.getSymbol().getName().equals(symbolName)));
		}

		public void hasRelocationAtAddress(String relaTable, long offset, ElfRelocationType type,
				String symbolName, long addend) {
			ElfRelaTable rela = getRelaTable(relaTable);

			assertTrue(rela.stream()
					.filter(r -> r.getOffset() == offset)
					.anyMatch(
						r -> r.getType() == type && r.getSymbol().getName().equals(symbolName) &&
							r.getAddend() == addend));
		}

		public void compareSectionSizes(String referenceSectionName,
				ElfObjectFile exportedFile, String exportedSectionName) throws Exception {
			long expectedSize = getSection(referenceSectionName).getSize();
			long actualSize = exportedFile.getSection(exportedSectionName).getSize();

			assertEquals(expectedSize, actualSize);
		}

		private ElfSection getSection(String name) {
			return elf.getSections()
					.stream()
					.filter(s -> s != null && s.getName().equals(name))
					.findFirst()
					.get();
		}

		private ElfSymbolTable getSymbolTable(String name) {
			return (ElfSymbolTable) getSection(name);
		}

		private ElfRelTable getRelTable(String name) {
			return (ElfRelTable) getSection(name);
		}

		private ElfRelaTable getRelaTable(String name) {
			return (ElfRelaTable) getSection(name);
		}
	}

	public class CoffObjectFile implements ObjectFile {
		private final CoffFile header;

		public CoffObjectFile(File file) throws IOException {
			this.header = new CoffFile.Parser(new FileInputStream(file)).parse();
		}

		@Override
		public byte[] getSectionBytes(String name) throws IOException {
			CoffBytes section = (CoffBytes) getSection(name);
			return section.getBytes();
		}

		public void hasSymbolAtAddress(String symbolName, String sectionName, int offset) {
			assertTrue(header.getSymbols()
					.stream()
					.filter(symbol -> symbol.getName().equals(symbolName))
					.anyMatch(symbol -> {
						CoffSection section =
							header.getSections().get(symbol.getSectionNumber());
						return section.getName().equals(sectionName) && symbol.getValue() == offset;
					}));
		}

		public void hasUndefinedSymbol(String symbolName) {
			assertTrue(header.getSymbols()
					.stream()
					.filter(symbol -> symbol.getName().equals(symbolName))
					.anyMatch(
						symbol -> symbol.getSectionNumber() == CoffSymbolSectionNumber.N_UNDEF));
		}

		public void hasRelocationAtAddress(String sectionName, long offset, CoffRelocationType type,
				String symbolName) {
			CoffSection section = getSection(sectionName);
			assertTrue(section.getRelocations()
					.stream()
					.filter(r -> r.getVirtualAddress() == offset)
					.anyMatch(r -> header.getSymbols()
							.get(r.getSymbolTableIndex())
							.getName()
							.equals(symbolName) &&
						r.getType() == type));
		}

		private CoffSection getSection(String name) {
			CoffSection section = header.getSections()
					.stream()
					.filter(s -> s.getName().equals(name))
					.findFirst()
					.orElse(null);
			assertNotNull(section);
			return section;
		}
	}

	public class OmfObjectFile implements ObjectFile {
		private final OmfFile omf;

		public OmfObjectFile(File file) throws IOException {
			this.omf = new OmfFile.Parser(new FileInputStream(file)).parse();
		}

		@Override
		public byte[] getSectionBytes(String name) throws IOException {
			List<OmfRecordLedata> ledatas = getLedataRecordsForSegment(name);
			if (ledatas.isEmpty()) {
				return new byte[0];
			}

			long maxEnd = 0;
			for (OmfRecordLedata ledata : ledatas) {
				long end = ledata.getDataOffset() + ledata.getData().length;
				if (end > maxEnd) {
					maxEnd = end;
				}
			}

			byte[] bytes = new byte[(int) maxEnd];
			for (OmfRecordLedata ledata : ledatas) {
				System.arraycopy(ledata.getData(), 0, bytes, (int) ledata.getDataOffset(),
					ledata.getData().length);
			}
			return bytes;
		}

		public OmfFile getOmfFile() {
			return omf;
		}

		public OmfLnamesData getLnamesData() {
			return OmfLnamesData.parse(omf);
		}

		public OmfExtdefData getExtdefData() {
			return OmfExtdefData.parse(omf);
		}

		public List<OmfPubdefData> getPubdefData() {
			return OmfPubdefData.parse(omf);
		}

		public List<OmfPubdefData> getPubdefDataForSegment(String segmentName) {
			List<OmfPubdefData> result = new ArrayList<>();
			for (OmfPubdefData pubdefData : getPubdefData()) {
				if (pubdefData.getSegment() != null &&
					pubdefData.getSegment().getSegmentName().equals(segmentName)) {
					result.add(pubdefData);
				}
			}
			return result;
		}

		/**
		 * Reconstructs logical segment data and absolute fixups from LEDATA/FIXUPP records.
		 */
		public OmfSegmentData getSegmentData(String segmentName) {
			OmfRecordSegdef segdef = getSegdefByName(segmentName);
			if (segdef == null) {
				return null;
			}
			return OmfSegmentData.parse(omf, segdef);
		}

		/**
		 * Gets the LEDATA record for a segment by name.
		 * Returns the first LEDATA found for the segment.
		 */
		public OmfRecordLedata getLedataForSegment(String segmentName) {
			List<OmfRecordLedata> ledatas = getLedataRecordsForSegment(segmentName);
			if (ledatas.isEmpty()) {
				return null;
			}
			return ledatas.get(0);
		}

		/**
		 * Gets all LEDATA records for a segment, ordered by data offset.
		 */
		public List<OmfRecordLedata> getLedataRecordsForSegment(String segmentName) {
			OmfRecordSegdef segdef = getSegdefByName(segmentName);
			if (segdef == null) {
				return Collections.emptyList();
			}

			List<OmfRecordLedata> ledatas = new ArrayList<>();
			for (OmfRecord record : omf.getElements()) {
				if (record instanceof OmfRecordLedata ledata) {
					if (ledata.getSegment() == segdef) {
						ledatas.add(ledata);
					}
				}
			}
			ledatas.sort((a, b) -> Long.compare(a.getDataOffset(), b.getDataOffset()));
			return ledatas;
		}

		/**
		 * Gets the FIXUPP record that follows a given LEDATA record.
		 */
		public OmfRecordFixupp getFixuppAfterLedata(OmfRecordLedata ledata) {
			List<OmfRecordFixupp> fixupps = getFixuppRecordsAfterLedata(ledata);
			if (fixupps.isEmpty()) {
				return null;
			}
			return fixupps.get(0);
		}

		/**
		 * Gets all FIXUPP records immediately following a given LEDATA record.
		 */
		public List<OmfRecordFixupp> getFixuppRecordsAfterLedata(OmfRecordLedata ledata) {
			List<OmfRecordFixupp> result = new ArrayList<>();
			List<OmfRecord> records = omf.getElements();
			int ledataIndex = records.indexOf(ledata);
			if (ledataIndex < 0) {
				return result;
			}

			for (int i = ledataIndex + 1; i < records.size(); i++) {
				OmfRecord nextRecord = records.get(i);
				if (nextRecord instanceof OmfRecordFixupp fixupp) {
					result.add(fixupp);
					continue;
				}
				break;
			}

			return result;
		}

		/**
		 * Gets all FIXUPP records for a segment by collecting FIXUPP records immediately
		 * following each LEDATA record in that segment.
		 */
		public List<OmfRecordFixupp> getFixuppRecordsForSegment(String segmentName) {
			List<OmfRecordFixupp> result = new ArrayList<>();
			for (OmfRecordLedata ledata : getLedataRecordsForSegment(segmentName)) {
				result.addAll(getFixuppRecordsAfterLedata(ledata));
			}
			return result;
		}

		/**
		 * Gets a SEGDEF record by segment name.
		 */
		public OmfRecordSegdef getSegdefByName(String name) {
			for (OmfRecord record : omf.getElements()) {
				if (record instanceof OmfRecordSegdef segdef) {
					if (segdef.getSegmentName().equals(name)) {
						return segdef;
					}
				}
			}
			return null;
		}

		/**
		 * Gets all EXTDEF records in the file.
		 */
		public List<OmfRecordExtdef> getExtdefRecords() {
			return omf.getElements()
					.stream()
					.filter(r -> r instanceof OmfRecordExtdef)
					.map(r -> (OmfRecordExtdef) r)
					.toList();
		}

		/**
		 * Gets all PUBDEF records in the file.
		 */
		public List<OmfRecordPubdef> getPubdefRecords() {
			return omf.getElements()
					.stream()
					.filter(r -> r instanceof OmfRecordPubdef)
					.map(r -> (OmfRecordPubdef) r)
					.toList();
		}

		/**
		 * Gets all external symbol names in order.
		 */
		public List<String> getExtdefNames() {
			return getExtdefData().getEntries().stream().map(OmfSubrecordExtdef::name).toList();
		}

		public int assertTargetExtdefIndicesMatchLogicalOrder(String segmentName) {
			List<OmfSubrecordExtdef> logicalExtdefEntries = getExtdefData().getEntries();
			int checked = 0;
			for (OmfRecordFixupp.FixupEntry fixupEntry : getFixupEntriesForSegment(segmentName)) {
				switch (fixupEntry.getTargetMethodEnum()) {
					case EXTDEF_INDEX:
						break;
					default:
						continue;
				}

				Integer extdefIndex = fixupEntry.getTargetDatum();
				assertNotNull("Expected EXTDEF target index in fixup", extdefIndex);
				assertTrue("EXTDEF target index must be positive", extdefIndex > 0);
				assertTrue("EXTDEF target index out of logical EXTDEF range",
					extdefIndex <= logicalExtdefEntries.size());

				String expectedName = logicalExtdefEntries.get(extdefIndex - 1).name();
				String resolvedName = getExtdefNameByIndex(extdefIndex);
				assertEquals("EXTDEF index-to-name mapping mismatch", expectedName, resolvedName);
				checked++;
			}
			return checked;
		}

		/**
		 * Checks if a public symbol exists in a segment at a given offset.
		 */
		public void hasPublicSymbol(String symbolName, String segmentName, long offset) {
			for (OmfRecordPubdef pubdef : getPubdefRecords()) {
				if (pubdef.getSegment() != null &&
					pubdef.getSegment().getSegmentName().equals(segmentName)) {
					for (OmfRecordPubdef.PublicSymbol sym : pubdef.getSymbols()) {
						if (sym.name().equals(symbolName) && sym.offset() == offset) {
							return; // Found it
						}
					}
				}
			}
			throw new AssertionError("Public symbol not found: " + symbolName +
				" in segment " + segmentName + " at offset " + offset);
		}

		/**
		 * Checks if an external symbol is defined.
		 */
		public void hasExternalSymbol(String symbolName) {
			List<String> extdefNames = getExtdefNames();
			assertTrue("External symbol not found: " + symbolName,
				extdefNames.contains(symbolName));
		}

		/**
		 * Checks if a fixup exists at a given offset within a segment.
		 */
		public void hasFixupAtOffset(String segmentName, int dataOffset) {
			List<OmfRecordLedata> ledatas = getLedataRecordsForSegment(segmentName);
			assertTrue("LEDATA not found for segment: " + segmentName, !ledatas.isEmpty());

			for (OmfRecordLedata ledata : ledatas) {
				long chunkStart = ledata.getDataOffset();
				long chunkEnd = chunkStart + ledata.getData().length;
				if (dataOffset < chunkStart || dataOffset >= chunkEnd) {
					continue;
				}

				for (OmfRecordFixupp fixupp : getFixuppRecordsAfterLedata(ledata)) {
					for (OmfRecordFixupp.FixupEntry entry : fixupp.getFixupEntries()) {
						long absolute = chunkStart + entry.getDataRecordOffset();
						if (absolute == dataOffset) {
							return; // Found it
						}
					}
				}
			}
			throw new AssertionError("Fixup not found at offset " + dataOffset +
				" in segment " + segmentName);
		}

		/**
		 * Gets all fixup data offsets for a segment in FIXUPP record order.
		 */
		public List<Integer> getFixupOffsetsForSegment(String segmentName) {
			List<Integer> offsets = new ArrayList<>();
			for (FixupContext ctx : getFixupContextsForSegment(segmentName)) {
				offsets.add(ctx.absoluteOffset);
			}
			assertTrue("No fixups found for segment: " + segmentName, !offsets.isEmpty());
			return offsets;
		}

		/**
		 * Gets all fixup entries for a segment in FIXUPP record order.
		 */
		public List<OmfRecordFixupp.FixupEntry> getFixupEntriesForSegment(String segmentName) {
			List<OmfRecordFixupp.FixupEntry> entries = new ArrayList<>();
			for (FixupContext ctx : getFixupContextsForSegment(segmentName)) {
				entries.add(ctx.entry);
			}
			assertTrue("No fixups found for segment: " + segmentName, !entries.isEmpty());
			return entries;
		}

		/**
		 * Compares all fixup offsets between reference and exported segments.
		 */
		public void compareFixupOffsets(String referenceSegmentName,
				OmfObjectFile exportedFile, String exportedSegmentName) {
			List<Integer> expectedOffsets = getFixupOffsetsForSegment(referenceSegmentName);
			List<Integer> actualOffsets =
				exportedFile.getFixupOffsetsForSegment(exportedSegmentName);
			assertEquals("Fixup offsets mismatch for segment " + exportedSegmentName,
				expectedOffsets, actualOffsets);
		}

		/**
		 * Compares complete fixup entries (all semantic fields) between reference and exported
		 * segments.
		 */
		public void compareFixupEntries(String referenceSegmentName,
				OmfObjectFile exportedFile, String exportedSegmentName) {
			List<FixupContext> expectedEntries =
				getFixupContextsForSegment(referenceSegmentName);
			List<FixupContext> remainingEntries =
				exportedFile.getFixupContextsForSegment(exportedSegmentName);

			assertEquals("Fixup entry count mismatch for segment " + exportedSegmentName,
				expectedEntries.size(), remainingEntries.size());

			for (int i = 0; i < expectedEntries.size(); i++) {
				FixupContext expected = expectedEntries.get(i);
				int matchIndex = -1;

				for (int j = 0; j < remainingEntries.size(); j++) {
					FixupContext actual = remainingEntries.get(j);
					if (fixupEntriesMatch(expected, actual, exportedFile)) {
						matchIndex = j;
						break;
					}
				}

				if (matchIndex < 0) {
					throw new AssertionError("No matching fixup found for segment " +
						exportedSegmentName + ": " + describeFixupEntry(expected, this));
				}

				remainingEntries.remove(matchIndex);
			}
		}

		private boolean fixupEntriesMatch(FixupContext expected,
				FixupContext actual, OmfObjectFile actualFile) {
			OmfRecordFixupp.FixupEntry expectedEntry = expected.entry;
			OmfRecordFixupp.FixupEntry actualEntry = actual.entry;

			return expected.absoluteOffset == actual.absoluteOffset &&
				expectedEntry.getLocationType() == actualEntry.getLocationType() &&
				expectedEntry.isSegmentRelative() == actualEntry.isSegmentRelative() &&
				expectedEntry.isFrameFromThread() == actualEntry.isFrameFromThread() &&
				expectedEntry.getFrameMethodEnum() == actualEntry.getFrameMethodEnum() &&
				expectedEntry.isTargetFromThread() == actualEntry.isTargetFromThread() &&
				expectedEntry.getTargetMethodEnum() == actualEntry.getTargetMethodEnum() &&
				java.util.Objects.equals(resolveFrameDatumForComparison(expectedEntry),
					actualFile.resolveFrameDatumForComparison(actualEntry)) &&
				java.util.Objects.equals(resolveTargetDatumForComparison(expectedEntry),
					actualFile.resolveTargetDatumForComparison(actualEntry)) &&
				java.util.Objects.equals(expectedEntry.getTargetDisplacement(),
					actualEntry.getTargetDisplacement());
		}

		private String describeFixupEntry(FixupContext context, OmfObjectFile file) {
			OmfRecordFixupp.FixupEntry entry = context.entry;
			return "offset=" + context.absoluteOffset +
				", localOffset=" + entry.getDataRecordOffset() +
				", locType=" + entry.getLocationType() +
				", segmentRelative=" + entry.isSegmentRelative() +
				", frameFromThread=" + entry.isFrameFromThread() +
				", frameMethod=" + entry.getFrameMethodEnum() +
				", frameDatum=" + file.resolveFrameDatumForComparison(entry) +
				", targetFromThread=" + entry.isTargetFromThread() +
				", targetMethod=" + entry.getTargetMethodEnum() +
				", targetDatum=" + file.resolveTargetDatumForComparison(entry) +
				", targetDisplacement=" + entry.getTargetDisplacement();
		}

		public List<Integer> getLedataChunkSizesForSegment(String segmentName) {
			List<Integer> sizes = new ArrayList<>();
			for (OmfRecordLedata ledata : getLedataRecordsForSegment(segmentName)) {
				sizes.add(ledata.getData().length);
			}
			return sizes;
		}

		private List<FixupContext> getFixupContextsForSegment(String segmentName) {
			List<FixupContext> contexts = new ArrayList<>();
			for (OmfRecordLedata ledata : getLedataRecordsForSegment(segmentName)) {
				long baseOffset = ledata.getDataOffset();
				for (OmfRecordFixupp fixupp : getFixuppRecordsAfterLedata(ledata)) {
					for (OmfRecordFixupp.FixupEntry entry : fixupp.getFixupEntries()) {
						int absoluteOffset = (int) (baseOffset + entry.getDataRecordOffset());
						contexts.add(new FixupContext(absoluteOffset, entry));
					}
				}
			}
			return contexts;
		}

		private static class FixupContext {
			final int absoluteOffset;
			final OmfRecordFixupp.FixupEntry entry;

			FixupContext(int absoluteOffset, OmfRecordFixupp.FixupEntry entry) {
				this.absoluteOffset = absoluteOffset;
				this.entry = entry;
			}
		}

		private Object resolveFrameDatumForComparison(OmfRecordFixupp.FixupEntry entry) {
			Integer datum = entry.getFrameDatum();
			if (datum == null) {
				return null;
			}

			switch (entry.getFrameMethodEnum()) {
				case SEGDEF_INDEX:
					return "SEG:" +
						normalizeSegmentName(omf.getSegmentByIndex(datum).getSegmentName());
				case GRPDEF_INDEX:
					return omf.getGroupByIndex(datum).getGroupName();
				case EXTDEF_INDEX:
					return getExtdefNameByIndex(datum);
				default:
					return datum;
			}
		}

		private Object resolveTargetDatumForComparison(OmfRecordFixupp.FixupEntry entry) {
			Integer datum = entry.getTargetDatum();
			if (datum == null) {
				return null;
			}

			switch (entry.getTargetMethodEnum()) {
				case SEGDEF_INDEX:
					return "SEG:" +
						normalizeSegmentName(omf.getSegmentByIndex(datum).getSegmentName());
				case GRPDEF_INDEX:
					return omf.getGroupByIndex(datum).getGroupName();
				case EXTDEF_INDEX:
					return getExtdefNameByIndex(datum);
				default:
					return datum;
			}
		}

		private String getExtdefNameByIndex(int index) {
			if (index <= 0) {
				throw new IndexOutOfBoundsException(index);
			}

			List<OmfSubrecordExtdef> extdefEntries = getExtdefData().getEntries();
			if (index > extdefEntries.size()) {
				throw new IndexOutOfBoundsException(index);
			}
			return extdefEntries.get(index - 1).name();
		}

		private String normalizeSegmentName(String segmentName) {
			String normalized = segmentName;
			while (normalized.startsWith("_") || normalized.startsWith(".")) {
				normalized = normalized.substring(1);
			}
			return normalized.toLowerCase();
		}
	}

	public static class IntegrationTestApplicationLayout extends GhidraTestApplicationLayout {
		public IntegrationTestApplicationLayout(File userSettingsDir)
				throws FileNotFoundException, IOException {
			super(userSettingsDir);
		}

		@Override
		protected Map<String, GModule> findGhidraModules() throws IOException {
			Map<String, GModule> modules = new HashMap<>(super.findGhidraModules());
			modules.put("Delinker",
				new GModule(applicationRootDirs, new ResourceFile(System.getProperty("user.dir"))));
			return Collections.unmodifiableMap(modules);
		}
	}

	@Before
	public void setUp() throws Exception {
		TestProgramManager.cleanDbTestDir();

		if (initialized == false) {
			initialize();
			initialized = true;
		}
	}

	@Override
	@After
	public void tearDown() throws Exception {
		if (dbHandle != null) {
			dbHandle.close();
		}
		dbHandle = null;
		program = null;

		TestProgramManager.cleanDbTestDir();
	}

	@Override
	protected Program getProgram() throws Exception {
		if (program != null) {
			return program;
		}

		File dbDir = new File(TestProgramManager.getDbTestDir(),
			NamingUtilities.mangle(getProgramName()) + ".db");
		File gzf = new File(getProgramName());

		PrivateDatabase pdb = new PrivateDatabase(dbDir, gzf, TaskMonitor.DUMMY);

		try {
			dbHandle = pdb.open(TaskMonitor.DUMMY);
			program = new ProgramDB(dbHandle, OpenMode.UPDATE, TaskMonitor.DUMMY, this);
		}
		catch (VersionException e) {
			if (!e.isUpgradable()) {
				throw e;
			}

			dbHandle = pdb.openForUpdate(TaskMonitor.DUMMY);
			program = new ProgramDB(dbHandle, OpenMode.UPGRADE, TaskMonitor.DUMMY, this);
			dbHandle.save(null, null, TaskMonitor.DUMMY);
			program.release(this);

			dbHandle = pdb.open(TaskMonitor.DUMMY);
			program = new ProgramDB(dbHandle, OpenMode.UPDATE, TaskMonitor.DUMMY, this);
		}

		return program;
	}

	@Override
	protected ApplicationLayout createApplicationLayout() throws IOException {
		return new IntegrationTestApplicationLayout(new File(getTestDirectoryPath()));
	}

	public static AddressSetView getAddressSetOfMemoryBlocks(Program program,
			List<String> memoryBlockNames) {
		AddressFactory addressFactory = program.getAddressFactory();
		AddressSet set = addressFactory.getAddressSet();
		set.clear();

		List<MemoryBlock> memoryBlocks =
			memoryBlockNames.stream().map(n -> program.getMemory().getBlock(n)).toList();
		for (MemoryBlock memoryBlock : memoryBlocks) {
			Address start = memoryBlock.getStart();
			Address end = memoryBlock.getEnd();

			set.add(addressFactory.getAddressSet(start, end));
		}

		return set;
	}

	public File exportObjectFile(AddressSetView set, Exporter exporter, List<Option> options)
			throws Exception {
		Program program = getProgram();
		MessageLog log = new MessageLog();
		RelocationTableSynthesizerAnalyzer analyzer = new RelocationTableSynthesizerAnalyzer();

		assertTrue(analyzer.added(program, set, TaskMonitor.DUMMY, log));

		if (options == null) {
			options = exporter.getOptions(new DomainObjectService() {
				@Override
				public DomainObject getDomainObject() {
					return program;
				}
			});
		}
		exporter.setOptions(options);

		File exportedFile = createTempFileForTest(".obj");
		assertTrue(exporter.export(exportedFile, program, set, TaskMonitor.DUMMY));

		return exportedFile;
	}
}
