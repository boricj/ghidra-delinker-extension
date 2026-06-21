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
package ghidra.app.util.exporter.freelist_allocator.coff.windows_msvc;

import static net.boricj.bft.coff.constants.CoffStorageClass.IMAGE_SYM_CLASS_EXTERNAL;
import static net.boricj.bft.coff.constants.CoffStorageClass.IMAGE_SYM_CLASS_STATIC;
import static net.boricj.bft.coff.machines.amd64.CoffRelocationType_amd64.IMAGE_REL_AMD64_ADDR64;
import static net.boricj.bft.coff.machines.amd64.CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;

import org.junit.Test;

import ghidra.DelinkerIntegrationTest;
import ghidra.app.util.exporter.CoffRelocatableObjectExporter;
import ghidra.program.model.address.AddressSetView;
import net.boricj.bft.coff.CoffFile;
import net.boricj.bft.coff.CoffRelocationTable;
import net.boricj.bft.coff.CoffSectionTable;
import net.boricj.bft.coff.CoffSymbolTable;
import net.boricj.bft.coff.constants.CoffMachine;
import net.boricj.bft.coff.sections.CoffBytes;
import net.boricj.bft.coff.sections.CoffUninitialized;

public class X64_Test extends DelinkerIntegrationTest {
	private static final File main_file =
		new File(
			"src/test/resources/programs/freelist-allocator/reference/coff/windows-msvc/x64/main.obj");

	@Override
	protected String getProgramName() {
		return "src/test/resources/programs/freelist-allocator/reference/coff/windows-msvc/x64/freelist-allocator.exe.gzf";
	}

	@Test
	public void test_main_obj() throws Exception {
		// Expected file.
		CoffFile expected = new CoffFile.Parser(new FileInputStream(main_file)).parse();

		CoffSectionTable expectedSections = expected.getSections();
		var expected_text = findSectionByName(expectedSections, ".text$mn", CoffBytes.class);
		var expected_rdata = findSectionByName(expectedSections, ".rdata", CoffBytes.class);
		var expected_data = findSectionByName(expectedSections, ".data", CoffBytes.class);
		// NOTE: MSVC does not emit a .bss section; s_heap is an external undefined symbol instead.

		// Actual file.
		AddressSetView set = findProgramModule("Object Files", "main.obj");
		File exportedFile = exportObjectFile(set, new CoffRelocatableObjectExporter(), null);
		CoffFile actual = new CoffFile.Parser(new FileInputStream(exportedFile)).parse();

		// COFF header.
		assertHeader(actual.getHeader(), CoffMachine.IMAGE_FILE_MACHINE_AMD64);

		CoffSectionTable actualSections = actual.getSections();
		var actual_text = findSectionByName(actualSections, ".text", CoffBytes.class);
		var actual_rdata = findSectionByName(actualSections, ".rdata", CoffBytes.class);
		var actual_data = findSectionByName(actualSections, ".data", CoffBytes.class);
		var actual_bss = findSectionByName(actualSections, ".bss", CoffUninitialized.class);

		CoffRelocationTable actual_rel_text = actual_text.getRelocations();
		CoffRelocationTable actual_rel_rdata = actual_rdata.getRelocations();
		CoffSymbolTable actual_symtab = actual.getSymbols();

		short actual_text_index = sectionNumber(actualSections, actual_text);
		short actual_rdata_index = sectionNumber(actualSections, actual_rdata);
		short actual_data_index = sectionNumber(actualSections, actual_data);
		short actual_bss_index = sectionNumber(actualSections, actual_bss);

		// Section flags.
		assertTrue(actual_text.getCharacteristics().isCntCode());
		assertTrue(actual_text.getCharacteristics().isMemExecute());
		assertTrue(actual_text.getCharacteristics().isMemRead());
		assertFalse(actual_text.getCharacteristics().isMemWrite());

		assertTrue(actual_rdata.getCharacteristics().isCntInitializedData());
		assertTrue(actual_rdata.getCharacteristics().isMemRead());
		assertFalse(actual_rdata.getCharacteristics().isMemExecute());
		assertFalse(actual_rdata.getCharacteristics().isMemWrite());

		assertTrue(actual_data.getCharacteristics().isCntInitializedData());
		assertTrue(actual_data.getCharacteristics().isMemRead());
		assertTrue(actual_data.getCharacteristics().isMemWrite());
		assertFalse(actual_data.getCharacteristics().isMemExecute());

		assertTrue(actual_bss.getCharacteristics().isCntUninitializedData());
		assertTrue(actual_bss.getCharacteristics().isMemRead());
		assertTrue(actual_bss.getCharacteristics().isMemWrite());
		assertFalse(actual_bss.getCharacteristics().isMemExecute());

		// .text symbols.
		assertSymbol(actual_symtab, actual_text_index, 0x00000000, ".text",
			IMAGE_SYM_CLASS_STATIC);
		assertSymbol(actual_symtab, actual_text_index, 0x00000000, "allocate_and_fill",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000070, "main",
			IMAGE_SYM_CLASS_EXTERNAL);

		// .rdata symbols.
		assertSymbol(actual_symtab, actual_rdata_index, 0x00000000, ".rdata",
			IMAGE_SYM_CLASS_STATIC);
		assertSymbol(actual_symtab, actual_rdata_index, 0x00000000, "s_snapshot_1",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_rdata_index, 0x00000180, "s_snapshot_2",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_rdata_index, 0x00000300, "s_snapshot_3",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_rdata_index, 0x00000480, "s_snapshot_4",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_rdata_index, 0x00000600, "s_snapshot_5",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_rdata_index, 0x00000780, "s_heap_ranges",
			IMAGE_SYM_CLASS_EXTERNAL);

		// .data symbols.
		assertSymbol(actual_symtab, actual_data_index, 0x00000000, ".data",
			IMAGE_SYM_CLASS_STATIC);
		assertSymbol(actual_symtab, actual_data_index, 0x00000000, "$SG10588",
			IMAGE_SYM_CLASS_EXTERNAL);

		// .bss symbols.
		assertSymbol(actual_symtab, actual_bss_index, 0x00000000, ".bss",
			IMAGE_SYM_CLASS_STATIC);
		assertSymbol(actual_symtab, actual_bss_index, 0x00000000, "s_heap",
			IMAGE_SYM_CLASS_EXTERNAL);

		// .text relocations.
		assertRel(actual_rel_text, actual_symtab, 0x00000025,
			IMAGE_REL_AMD64_REL32, "freelist_alloc");
		assertRel(actual_rel_text, actual_symtab, 0x00000053,
			IMAGE_REL_AMD64_REL32, "memset");
		assertRel(actual_rel_text, actual_symtab, 0x0000007a,
			IMAGE_REL_AMD64_REL32, "__security_cookie");
		assertRel(actual_rel_text, actual_symtab, 0x0000008c,
			IMAGE_REL_AMD64_REL32, "s_heap");
		assertRel(actual_rel_text, actual_symtab, 0x000000a0,
			IMAGE_REL_AMD64_REL32, "freelist_init");
		assertRel(actual_rel_text, actual_symtab, 0x000000b0,
			IMAGE_REL_AMD64_REL32, "s_heap_ranges");
		assertRel(actual_rel_text, actual_symtab, 0x000000c0,
			IMAGE_REL_AMD64_REL32, "s_heap_ranges");
		assertRel(actual_rel_text, actual_symtab, 0x000000dc,
			IMAGE_REL_AMD64_REL32, "s_heap_ranges");
		assertRel(actual_rel_text, actual_symtab, 0x000000ed,
			IMAGE_REL_AMD64_REL32, "memcmp");
		assertRel(actual_rel_text, actual_symtab, 0x00000175,
			IMAGE_REL_AMD64_REL32, "s_heap_ranges");
		assertRel(actual_rel_text, actual_symtab, 0x00000185,
			IMAGE_REL_AMD64_REL32, "s_heap_ranges");
		assertRel(actual_rel_text, actual_symtab, 0x000001a1,
			IMAGE_REL_AMD64_REL32, "s_heap_ranges");
		assertRel(actual_rel_text, actual_symtab, 0x000001b2,
			IMAGE_REL_AMD64_REL32, "memcmp");
		assertRel(actual_rel_text, actual_symtab, 0x000001fb,
			IMAGE_REL_AMD64_REL32, "freelist_free");
		assertRel(actual_rel_text, actual_symtab, 0x0000020e,
			IMAGE_REL_AMD64_REL32, "s_heap_ranges");
		assertRel(actual_rel_text, actual_symtab, 0x0000021e,
			IMAGE_REL_AMD64_REL32, "s_heap_ranges");
		assertRel(actual_rel_text, actual_symtab, 0x0000023a,
			IMAGE_REL_AMD64_REL32, "s_heap_ranges");
		assertRel(actual_rel_text, actual_symtab, 0x0000024b,
			IMAGE_REL_AMD64_REL32, "memcmp");
		assertRel(actual_rel_text, actual_symtab, 0x00000294,
			IMAGE_REL_AMD64_REL32, "freelist_free");
		assertRel(actual_rel_text, actual_symtab, 0x000002a7,
			IMAGE_REL_AMD64_REL32, "s_heap_ranges");
		assertRel(actual_rel_text, actual_symtab, 0x000002b7,
			IMAGE_REL_AMD64_REL32, "s_heap_ranges");
		assertRel(actual_rel_text, actual_symtab, 0x000002d3,
			IMAGE_REL_AMD64_REL32, "s_heap_ranges");
		assertRel(actual_rel_text, actual_symtab, 0x000002e4,
			IMAGE_REL_AMD64_REL32, "memcmp");
		assertRel(actual_rel_text, actual_symtab, 0x0000032d,
			IMAGE_REL_AMD64_REL32, "freelist_free");
		assertRel(actual_rel_text, actual_symtab, 0x00000340,
			IMAGE_REL_AMD64_REL32, "s_heap_ranges");
		assertRel(actual_rel_text, actual_symtab, 0x00000350,
			IMAGE_REL_AMD64_REL32, "s_heap_ranges");
		assertRel(actual_rel_text, actual_symtab, 0x0000036c,
			IMAGE_REL_AMD64_REL32, "s_heap_ranges");
		assertRel(actual_rel_text, actual_symtab, 0x0000037d,
			IMAGE_REL_AMD64_REL32, "memcmp");
		assertRel(actual_rel_text, actual_symtab, 0x0000038f,
			IMAGE_REL_AMD64_REL32, "$SG10588");
		assertRel(actual_rel_text, actual_symtab, 0x00000394,
			IMAGE_REL_AMD64_REL32, "puts");
		assertRel(actual_rel_text, actual_symtab, 0x000003a9,
			IMAGE_REL_AMD64_REL32, "__security_check_cookie");
		assertEquals(31, actual_rel_text.size());

		// .rdata relocations.
		assertRel(actual_rel_rdata, actual_symtab, 0x00000180,
			IMAGE_REL_AMD64_ADDR64, "s_heap");
		assertRel(actual_rel_rdata, actual_symtab, 0x000001a0,
			IMAGE_REL_AMD64_ADDR64, "s_heap");
		assertRel(actual_rel_rdata, actual_symtab, 0x000001c0,
			IMAGE_REL_AMD64_ADDR64, "s_heap");
		assertRel(actual_rel_rdata, actual_symtab, 0x000001e0,
			IMAGE_REL_AMD64_ADDR64, "s_heap");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000200,
			IMAGE_REL_AMD64_ADDR64, "s_heap");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000240,
			IMAGE_REL_AMD64_ADDR64, "s_heap");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000280,
			IMAGE_REL_AMD64_ADDR64, "s_heap");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000300,
			IMAGE_REL_AMD64_ADDR64, "s_heap");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000320,
			IMAGE_REL_AMD64_ADDR64, "s_heap");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000340,
			IMAGE_REL_AMD64_ADDR64, "s_heap");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000360,
			IMAGE_REL_AMD64_ADDR64, "s_heap");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000380,
			IMAGE_REL_AMD64_ADDR64, "s_heap");
		assertRel(actual_rel_rdata, actual_symtab, 0x000003c0,
			IMAGE_REL_AMD64_ADDR64, "s_heap");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000400,
			IMAGE_REL_AMD64_ADDR64, "s_heap");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000480,
			IMAGE_REL_AMD64_ADDR64, "s_heap");
		assertRel(actual_rel_rdata, actual_symtab, 0x000004a0,
			IMAGE_REL_AMD64_ADDR64, "s_heap");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000500,
			IMAGE_REL_AMD64_ADDR64, "s_heap");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000780,
			IMAGE_REL_AMD64_ADDR64, "s_snapshot_1");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000788,
			IMAGE_REL_AMD64_ADDR64, "s_snapshot_1");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000790,
			IMAGE_REL_AMD64_ADDR64, "s_snapshot_2");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000798,
			IMAGE_REL_AMD64_ADDR64, "s_snapshot_2");
		assertRel(actual_rel_rdata, actual_symtab, 0x000007a0,
			IMAGE_REL_AMD64_ADDR64, "s_snapshot_3");
		assertRel(actual_rel_rdata, actual_symtab, 0x000007a8,
			IMAGE_REL_AMD64_ADDR64, "s_snapshot_3");
		assertRel(actual_rel_rdata, actual_symtab, 0x000007b0,
			IMAGE_REL_AMD64_ADDR64, "s_snapshot_4");
		assertRel(actual_rel_rdata, actual_symtab, 0x000007b8,
			IMAGE_REL_AMD64_ADDR64, "s_snapshot_4");
		assertRel(actual_rel_rdata, actual_symtab, 0x000007c0,
			IMAGE_REL_AMD64_ADDR64, "s_snapshot_5");
		assertRel(actual_rel_rdata, actual_symtab, 0x000007c8,
			IMAGE_REL_AMD64_ADDR64, "s_snapshot_5");
		assertEquals(27, actual_rel_rdata.size());

		// .text bytes.
		assertSectionBytes(expected_text, 0x00000000,
			actual_text, 0x00000000, (int) expected_text.getLength(),
			new Patch(0x00000159,
				new byte[] { (byte) 0xa3, (byte) 0xfe, (byte) 0xff, (byte) 0xff }));

		// .rdata bytes.
		assertSectionBytes(expected_rdata, actual_rdata);

		// .data bytes.
		assertSectionBytes(expected_data, actual_data);

		// .bss bytes.
		assertEquals(0x180L, actual_bss.getVirtualSize());
	}
}
