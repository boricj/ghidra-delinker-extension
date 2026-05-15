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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.junit.After;
import org.junit.Before;

import db.DBHandle;
import generic.jar.ResourceFile;
import ghidra.app.analyzers.RelocationTableSynthesizerAnalyzer;
import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.GModule;
import ghidra.framework.data.OpenMode;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.db.PrivateDatabase;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.module.TreeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractProgramBasedTest;
import ghidra.test.TestProgramManager;
import ghidra.util.NamingUtilities;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;
import net.boricj.bft.TestUtils;
import net.boricj.bft.coff.CoffHeader;
import net.boricj.bft.coff.CoffRelocationTable;
import net.boricj.bft.coff.CoffRelocationTable.CoffRel;
import net.boricj.bft.coff.CoffSection;
import net.boricj.bft.coff.CoffSectionTable;
import net.boricj.bft.coff.CoffSymbolTable;
import net.boricj.bft.coff.CoffSymbolTable.CoffSymbol;
import net.boricj.bft.coff.constants.CoffMachine;
import net.boricj.bft.coff.constants.CoffRelocationType;
import net.boricj.bft.coff.constants.CoffStorageClass;
import net.boricj.bft.coff.sections.CoffBytes;
import net.boricj.bft.elf.ElfHeader;
import net.boricj.bft.elf.ElfSection;
import net.boricj.bft.elf.ElfSectionTable;
import net.boricj.bft.elf.constants.ElfClass;
import net.boricj.bft.elf.constants.ElfData;
import net.boricj.bft.elf.constants.ElfMachine;
import net.boricj.bft.elf.constants.ElfSymbolBinding;
import net.boricj.bft.elf.constants.ElfSymbolType;
import net.boricj.bft.elf.constants.ElfSymbolVisibility;
import net.boricj.bft.elf.constants.ElfType;
import net.boricj.bft.elf.sections.ElfProgBits;
import net.boricj.bft.elf.sections.ElfRelTable;
import net.boricj.bft.elf.sections.ElfRelaTable;
import net.boricj.bft.elf.sections.ElfSymbolTable;
import net.boricj.bft.omf.OmfFile;
import net.boricj.bft.omf.OmfSegmentData;
import net.boricj.bft.omf.OmfRecord;
import net.boricj.bft.omf.records.OmfRecordExtdef;
import net.boricj.bft.omf.records.OmfRecordPubdef;
import net.boricj.bft.omf.records.OmfRecordFixupp.FixupEntry;
import net.boricj.bft.omf.records.OmfRecordFixupp.TargetMethod;
import net.boricj.bft.omf.records.OmfRecordGrpdef;
import net.boricj.bft.omf.records.OmfRecordSegdef;
import utility.application.ApplicationLayout;

public abstract class DelinkerIntegrationTest extends AbstractProgramBasedTest {
	private static DBHandle dbHandle = null;
	private static Program program = null;
	private static boolean initialized = false;

	//
	// Ghidra stuff.
	//
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

	//
	// Generic helper methods.
	//

	public record Patch(int offset, byte[] bytes) {}

	public record Rel(int offset, Object type, String symbol) {}

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

	public AddressSetView findProgramModule(String root, String... path) throws Exception {
		TreeManager treeManager = ((ProgramDB) getProgram()).getTreeManager();
		ProgramModule module = treeManager.getRootModule(root);
		for (String name : path) {
			module = (ProgramModule) module.getChildren()[module.getIndex(name)];
		}
		return module.getAddressSet();
	}

	//
	// COFF helper methods.
	//

	public static void assertHeader(CoffHeader header, CoffMachine machine) {
		assertEquals(machine, header.getMachine());
	}

	public static short sectionNumber(CoffSectionTable sections, CoffSection section) {
		int index = sections.getElements().indexOf(section);
		assertTrue(index >= 0);
		return (short) (index + 1);
	}

	public static <T> T findSectionByName(CoffSectionTable sections, String name, Class<T> clazz) {
		var section =
			sections.getElements().stream().filter(s -> s.getName().equals(name)).findFirst();
		assertTrue(section.isPresent());
		assertTrue(clazz.isInstance(section.get()));
		return clazz.cast(section.get());
	}

	public static void assertSymbol(CoffSymbolTable symtab, short sectionNumber, int value,
			String name, CoffStorageClass storageClass) {
		var symbol =
			symtab.getElements().stream().filter(s -> s.getName().equals(name)).findFirst();
		assertTrue(symbol.isPresent());
		assertEquals(sectionNumber, symbol.get().getSectionNumber());
		assertEquals(value, symbol.get().getValue());
		assertEquals(storageClass, symbol.get().getStorageClass());
	}

	public static void assertUndefined(CoffSymbolTable symtab, String name) {
		assertSymbol(symtab, CoffSymbol.IMAGE_SYM_UNDEFINED, 0, name,
			CoffStorageClass.IMAGE_SYM_CLASS_EXTERNAL);
	}

	public static void assertRel(CoffRelocationTable rels, CoffSymbolTable symtab, int offset,
			CoffRelocationType type, String symbolName) {
		CoffRel rel =
			rels.getElements()
					.stream()
					.filter(r -> r.getVirtualAddress() == offset)
					.findFirst()
					.orElse(null);
		assertTrue(rel != null);
		assertEquals(type, rel.getType());
		assertEquals(symbolName, symtab.get(rel.getSymbolTableIndex()).getName());
	}

	public static void assertSectionBytes(CoffBytes expected, int expectedOffset, CoffBytes actual,
			int actualOffset, int length, Patch... patches) {
		byte[] expectedBytes = new byte[length];
		System.arraycopy(expected.getBytes(), expectedOffset, expectedBytes, 0, length);
		for (Patch patch : patches) {
			System.arraycopy(patch.bytes(), 0, expectedBytes, patch.offset(), patch.bytes().length);
		}
		byte[] actualBytes = new byte[length];
		System.arraycopy(actual.getBytes(), actualOffset, actualBytes, 0, length);
		TestUtils.assertArrayEquals(expectedBytes, actualBytes);
	}

	public static void assertSectionBytes(CoffBytes expected, CoffBytes actual) {
		TestUtils.assertArrayEquals(expected.getBytes(), actual.getBytes());
	}

	//
	// ELF helper methods.
	//

	public static void assertHeader(ElfHeader expected, ElfClass clazz, ElfData data, ElfType type,
			ElfMachine machine) {
		assertEquals(expected.getIdentClass(), clazz);
		assertEquals(expected.getIdentData(), data);
		assertEquals(expected.getType(), type);
		assertEquals(expected.getMachine(), machine);
	}

	public static int sectionNumber(ElfSectionTable sections, ElfSection section) {
		int index = sections.getElements().indexOf(section);
		assertTrue(index >= 0);
		return index;
	}

	public static <T> T findSectionByName(ElfSectionTable sections, String name, Class<T> clazz) {
		var section = sections.stream().filter(s -> s.getName().equals(name)).findFirst();
		assertTrue(section.isPresent());
		assertTrue(clazz.isInstance(section.get()));
		return clazz.cast(section.get());
	}

	public static void assertSymbol(ElfSymbolTable symtab, int index, long value, long size,
			ElfSymbolType type, ElfSymbolVisibility visibility, ElfSymbolBinding binding) {
		var sym = symtab.stream().filter(s -> s.getIndex() == index).findFirst();
		assertTrue(sym.isPresent());
		assertEquals(sym.get().getValue(), value);
		assertEquals(sym.get().getSize(), size);
		assertEquals(sym.get().getType(), type);
		assertEquals(sym.get().getVisibility(), visibility);
		assertEquals(sym.get().getBinding(), binding);
	}

	public static void assertSymbol(ElfSymbolTable symtab, int index, long value, String name,
			long size, ElfSymbolType type, ElfSymbolVisibility visibility,
			ElfSymbolBinding binding) {
		var sym = symtab.stream().filter(s -> s.getName().equals(name)).findFirst();
		assertTrue(sym.isPresent());
		assertEquals(sym.get().getName(), name);
		assertEquals(sym.get().getValue(), value);
		assertEquals(sym.get().getSize(), size);
		assertEquals(sym.get().getIndex(), index);
		assertEquals(sym.get().getType(), type);
		assertEquals(sym.get().getVisibility(), visibility);
		assertEquals(sym.get().getBinding(), binding);
	}

	public static <T> void assertRel(ElfRelTable table, int offset, T type,
			String symbol) {
		var rel = table.stream().filter(r -> r.getOffset() == offset).findFirst();
		assertTrue(rel.isPresent());
		assertEquals(rel.get().getOffset(), offset);
		assertEquals(rel.get().getType(), type);
		assertEquals(rel.get().getSymbol().getName(), symbol);
	}

	public static void assertRels(ElfRelTable table, Rel... expected) {
		var actual = table.stream()
				.map(r -> new Rel((int) r.getOffset(), r.getType(), r.getSymbol().getName()))
				.toList();
		assertTrue(actual.size() >= expected.length);

		var expectedCounts = new HashMap<Rel, Integer>();
		for (var rel : expected) {
			expectedCounts.merge(rel, 1, Integer::sum);
		}

		for (int start = 0; start <= actual.size() - expected.length; start++) {
			var windowCounts = new HashMap<Rel, Integer>();
			for (int i = start; i < start + expected.length; i++) {
				windowCounts.merge(actual.get(i), 1, Integer::sum);
			}

			if (windowCounts.equals(expectedCounts)) {
				return;
			}
		}

		assertTrue("Expected relocations were not found in any contiguous range", false);
	}

	public static <T> void assertRela(ElfRelaTable table, int offset, T type,
			String symbol, long addend) {
		var rel = table.stream().filter(r -> r.getOffset() == offset).findFirst();
		assertTrue(rel.isPresent());
		assertEquals(rel.get().getOffset(), offset);
		assertEquals(rel.get().getType(), type);
		assertEquals(rel.get().getSymbol().getName(), symbol);
		assertEquals(rel.get().getAddend(), addend);
	}

	public static void assertSectionBytes(ElfProgBits expected, int expected_offset,
			ElfProgBits actual, int actual_offset, int length, Patch... patches) {
		byte[] expectedBytes = new byte[length];
		System.arraycopy(expected.getBytes(), expected_offset, expectedBytes, 0, length);
		for (Patch patch : patches) {
			System.arraycopy(patch.bytes, 0, expectedBytes, patch.offset, patch.bytes.length);
		}
		byte[] actualBytes = new byte[length];
		System.arraycopy(actual.getBytes(), actual_offset, actualBytes, 0, length);
		TestUtils.assertArrayEquals(expectedBytes, actualBytes);
	}

	public static void assertSectionBytes(ElfProgBits expected, ElfProgBits actual) {
		byte[] expectedBytes = expected.getBytes();
		byte[] actualBytes = actual.getBytes();
		TestUtils.assertArrayEquals(expectedBytes, actualBytes);
	}

	//
	// OMF helper methods.
	//

	public record OmfFixupDescriptor(int offset, int locationType, boolean segmentRelative,
			String targetName) {
		public OmfFixupDescriptor(int offset, boolean segmentRelative, String targetName) {
			this(offset, -1, segmentRelative, targetName);
		}
	}

	public static OmfRecordSegdef findSegmentByName(OmfFile file, String segmentName) {
		for (OmfRecord record : file.getElements()) {
			if (record instanceof OmfRecordSegdef segdef &&
				Objects.equals(segdef.getSegmentName(), segmentName)) {
				return segdef;
			}
		}
		assertTrue("Missing segment: " + segmentName, false);
		return null;
	}

	public static void assertSegdefIsDwordPublicUse32(OmfFile file, String segmentName) {
		OmfRecordSegdef segdef = findSegmentByName(file, segmentName);
		int attributes = segdef.getAttributes();

		int alignmentCode = (attributes >> 5) & 0x07;
		int combineCode = (attributes >> 2) & 0x07;
		boolean isBigSegment = (attributes & 0x02) != 0;
		boolean isUse32 = (attributes & 0x01) != 0;

		assertEquals(5, alignmentCode);
		assertEquals(2, combineCode);
		assertEquals(false, isBigSegment);
		assertEquals(true, isUse32);
	}

	public static OmfSegmentData segmentDataByName(OmfFile file, String segmentName) {
		return OmfSegmentData.parse(file, findSegmentByName(file, segmentName));
	}

	public static void assertPublicSymbol(OmfFile file, String segmentName, String symbolName,
			long offset) {
		// Scan PUBDEF records for the symbol
		OmfRecordSegdef targetSegment = findSegmentByName(file, segmentName);
		boolean found = false;
		for (OmfRecord record : file.getElements()) {
			if (record instanceof OmfRecordPubdef pubdef && pubdef.getSegment() == targetSegment) {
				if (pubdef.getSymbols()
						.stream()
						.anyMatch(sym -> sym.name().equals(symbolName) && sym.offset() == offset)) {
					found = true;
					break;
				}
			}
		}
		assertTrue("Missing public symbol: " + symbolName + " @ " + segmentName + ":" +
			Long.toHexString(offset), found);
	}

	public static List<String> externalSymbolNames(OmfFile file) {
		// Scan EXTDEF records for external symbol names
		List<String> names = new ArrayList<>();
		for (OmfRecord record : file.getElements()) {
			if (record instanceof OmfRecordExtdef extdef) {
				for (var extdefEntry : extdef.getElements()) {
					names.add(extdefEntry.name());
				}
			}
		}
		return names;
	}

	public static void assertExternalSymbol(OmfFile file, String symbolName) {
		assertTrue("Missing external symbol: " + symbolName,
			externalSymbolNames(file).contains(symbolName));
	}

	public static List<OmfFixupDescriptor> omfFixupSpecs(OmfFile file, String segmentName) {
		OmfSegmentData segmentData = segmentDataByName(file, segmentName);
		List<String> extdefs = externalSymbolNames(file);
		List<OmfFixupDescriptor> fixups = new java.util.ArrayList<>();

		for (OmfSegmentData.FixupAtOffset fixupAtOffset : segmentData.getFixups()) {
			FixupEntry entry = fixupAtOffset.entry();
			assertFalse("Thread-based target fixups are not expected in this test",
				entry.isTargetFromThread());
			assertFalse("Thread-based frame fixups are not expected in this test",
				entry.isFrameFromThread());

			fixups.add(new OmfFixupDescriptor(
				fixupAtOffset.segmentOffset(),
				entry.getLocationType(),
				entry.isSegmentRelative(),
				resolveOmfTargetName(file, extdefs, entry)));
		}

		fixups.sort(java.util.Comparator
				.comparingInt(OmfFixupDescriptor::offset)
				.thenComparingInt(OmfFixupDescriptor::locationType)
				.thenComparing(OmfFixupDescriptor::segmentRelative)
				.thenComparing(OmfFixupDescriptor::targetName));
		return fixups;
	}

	public static void assertOmfFixup(List<OmfFixupDescriptor> fixups, int offset,
			boolean segmentRelative, String targetName) {
		boolean found = fixups.stream()
				.anyMatch(fixup -> fixup.offset() == offset &&
					fixup.segmentRelative() == segmentRelative &&
					Objects.equals(fixup.targetName(), targetName));
		assertTrue("Missing OMF fixup: offset=0x" + Integer.toHexString(offset) +
			", segmentRelative=" + segmentRelative + ", target=" + targetName, found);
	}

	public static void assertOmfFixups(List<OmfFixupDescriptor> fixups,
			OmfFixupDescriptor... expectedFixups) {
		for (OmfFixupDescriptor expectedFixup : expectedFixups) {
			assertOmfFixup(fixups, expectedFixup.offset(), expectedFixup.segmentRelative(),
				expectedFixup.targetName());
		}
		assertEquals(expectedFixups.length, fixups.size());
	}

	private static String resolveOmfTargetName(OmfFile file, List<String> extdefs,
			FixupEntry entry) {
		TargetMethod method = entry.getTargetMethodEnum();
		Integer datum = entry.getTargetDatum();
		assertTrue("Fixup target datum is required", datum != null);

		if (method == TargetMethod.EXTDEF_INDEX) {
			int extIndex = datum.intValue() - 1;
			assertTrue("EXTDEF index out of range: " + datum,
				extIndex >= 0 && extIndex < extdefs.size());
			return "E:" + extdefs.get(extIndex);
		}
		if (method == TargetMethod.SEGDEF_INDEX) {
			String segName = getOmfSegmentByIndex(file, datum.intValue()).getSegmentName();
			return "S:" + normalizeOmfSegmentName(segName);
		}
		if (method == TargetMethod.GRPDEF_INDEX) {
			return "G:" + getOmfGroupByIndex(file, datum.intValue()).getGroupName();
		}
		return "F:" + datum;
	}

	private static OmfRecordSegdef getOmfSegmentByIndex(OmfFile file, int index) {
		int current = 1;
		for (OmfRecord record : file.getElements()) {
			if (record instanceof OmfRecordSegdef segdef) {
				if (current == index) {
					return segdef;
				}
				current++;
			}
		}
		throw new IndexOutOfBoundsException("SEGDEF index out of range: " + index);
	}

	private static OmfRecordGrpdef getOmfGroupByIndex(OmfFile file, int index) {
		int current = 1;
		for (OmfRecord record : file.getElements()) {
			if (record instanceof OmfRecordGrpdef grpdef) {
				if (current == index) {
					return grpdef;
				}
				current++;
			}
		}
		throw new IndexOutOfBoundsException("GRPDEF index out of range: " + index);
	}

	private static String normalizeOmfSegmentName(String segmentName) {
		String normalized = segmentName;
		if (normalized.startsWith("_")) {
			normalized = normalized.substring(1);
		}
		if (normalized.startsWith(".")) {
			normalized = normalized.substring(1);
		}
		return normalized.toLowerCase();
	}

	public static void assertSegmentBytes(OmfSegmentData expected, OmfSegmentData actual) {
		TestUtils.assertArrayEquals(expected.getBytes(), actual.getBytes());
	}

	public static void assertSegmentBytes(OmfSegmentData expected, int expectedOffset,
			OmfSegmentData actual, int actualOffset, int length, Patch... patches) {
		byte[] expectedBytes = new byte[length];
		System.arraycopy(expected.getBytes(), expectedOffset, expectedBytes, 0, length);
		for (Patch patch : patches) {
			System.arraycopy(patch.bytes(), 0, expectedBytes, patch.offset(), patch.bytes().length);
		}
		byte[] actualBytes = new byte[length];
		System.arraycopy(actual.getBytes(), actualOffset, actualBytes, 0, length);
		TestUtils.assertArrayEquals(expectedBytes, actualBytes);
	}
}
