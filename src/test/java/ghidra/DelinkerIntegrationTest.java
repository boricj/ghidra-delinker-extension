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

		File exportedFile = createTempFileForTest(".o");
		assertTrue(exporter.export(exportedFile, program, set, TaskMonitor.DUMMY));

		return exportedFile;
	}
}
