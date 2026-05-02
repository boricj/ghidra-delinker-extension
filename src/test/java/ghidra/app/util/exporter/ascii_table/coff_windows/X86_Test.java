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
package ghidra.app.util.exporter.ascii_table.coff_windows;

import static net.boricj.bft.coff.constants.CoffStorageClass.IMAGE_SYM_CLASS_EXTERNAL;
import static net.boricj.bft.coff.machines.i386.CoffRelocationType_i386.IMAGE_REL_I386_DIR32;
import static net.boricj.bft.coff.machines.i386.CoffRelocationType_i386.IMAGE_REL_I386_REL32;
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

public class X86_Test extends DelinkerIntegrationTest {
	private static final File main_file =
		new File(
			"src/test/resources/programs/ascii-table/reference/coff/windows-msvc/x86/main.obj");

	private static final File openbsd_ctype_file =
		new File(
			"src/test/resources/programs/ascii-table/reference/coff/windows-msvc/x86/openbsd_ctype.obj");

	@Override
	protected String getProgramName() {
		return "src/test/resources/programs/ascii-table/reference/coff/windows-msvc/x86/ascii-table.exe.gzf";
	}

	@Test
	public void test_main_obj() throws Exception {
		// Expected file.
		CoffFile expected = new CoffFile.Parser(new FileInputStream(main_file)).parse();

		CoffSectionTable expectedSections = expected.getSections();
		var expected_text = findSectionByName(expectedSections, ".text$mn", CoffBytes.class);
		var expected_rdata = findSectionByName(expectedSections, ".rdata", CoffBytes.class);
		var expected_data = findSectionByName(expectedSections, ".data", CoffBytes.class);

		// Actual file.
		AddressSetView set = findProgramModule("Object Files", "main.obj");
		File exportedFile = exportObjectFile(set, new CoffRelocatableObjectExporter(), null);
		CoffFile actual = new CoffFile.Parser(new FileInputStream(exportedFile)).parse();

		// COFF header.
		assertHeader(actual.getHeader(), CoffMachine.IMAGE_FILE_MACHINE_I386);

		CoffSectionTable actualSections = actual.getSections();
		var actual_text = findSectionByName(actualSections, ".text", CoffBytes.class);
		var actual_rdata = findSectionByName(actualSections, ".rdata", CoffBytes.class);
		var actual_data = findSectionByName(actualSections, ".data", CoffBytes.class);

		CoffRelocationTable actual_rel_text = actual_text.getRelocations();
		CoffRelocationTable actual_rel_rdata = actual_rdata.getRelocations();
		CoffSymbolTable actual_symtab = actual.getSymbols();

		short actual_text_index = sectionNumber(actualSections, actual_text);
		short actual_rdata_index = sectionNumber(actualSections, actual_rdata);
		short actual_data_index = sectionNumber(actualSections, actual_data);

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

		// Defined symbols.
		assertSymbol(actual_symtab, actual_text_index, 0x00000000, "_print_number",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000070, "_print_ascii_entry",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000120, "_main",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_rdata_index, 0x00000000, "_NUM_ASCII_PROPERTIES",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_rdata_index, 0x00000008, "_s_ascii_properties",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_data_index, 0x00000000, "_COLUMNS",
			IMAGE_SYM_CLASS_EXTERNAL);

		// Undefined symbols.
		assertUndefined(actual_symtab, "_openbsd_isalnum");
		assertUndefined(actual_symtab, "_openbsd_isalpha");
		assertUndefined(actual_symtab, "_openbsd_iscntrl");
		assertUndefined(actual_symtab, "_openbsd_isdigit");
		assertUndefined(actual_symtab, "_openbsd_isgraph");
		assertUndefined(actual_symtab, "_openbsd_islower");
		assertUndefined(actual_symtab, "_openbsd_isprint");
		assertUndefined(actual_symtab, "_openbsd_ispunct");
		assertUndefined(actual_symtab, "_openbsd_isspace");
		assertUndefined(actual_symtab, "_openbsd_isupper");
		assertUndefined(actual_symtab, "_putchar");

		// .text relocations.
		assertRel(actual_rel_text, actual_symtab, 0x00000047,
			IMAGE_REL_I386_REL32, "_putchar");
		assertRel(actual_rel_text, actual_symtab, 0x00000058,
			IMAGE_REL_I386_REL32, "_putchar");
		assertRel(actual_rel_text, actual_symtab, 0x0000007c,
			IMAGE_REL_I386_REL32, "_print_number");
		assertRel(actual_rel_text, actual_symtab, 0x00000086,
			IMAGE_REL_I386_REL32, "_putchar");
		assertRel(actual_rel_text, actual_symtab, 0x00000093,
			IMAGE_REL_I386_REL32, "_openbsd_isgraph");
		assertRel(actual_rel_text, actual_symtab, 0x000000a4,
			IMAGE_REL_I386_REL32, "_putchar");
		assertRel(actual_rel_text, actual_symtab, 0x000000b0,
			IMAGE_REL_I386_REL32, "_putchar");
		assertRel(actual_rel_text, actual_symtab, 0x000000ba,
			IMAGE_REL_I386_REL32, "_putchar");
		assertRel(actual_rel_text, actual_symtab, 0x00000103,
			IMAGE_REL_I386_REL32, "_putchar");
		assertRel(actual_rel_text, actual_symtab, 0x0000010f,
			IMAGE_REL_I386_REL32, "_putchar");
		assertRel(actual_rel_text, actual_symtab, 0x00000147,
			IMAGE_REL_I386_DIR32, "_COLUMNS");
		assertRel(actual_rel_text, actual_symtab, 0x00000154,
			IMAGE_REL_I386_DIR32, "_COLUMNS");
		assertRel(actual_rel_text, actual_symtab, 0x00000164,
			IMAGE_REL_I386_DIR32, "_COLUMNS");
		assertRel(actual_rel_text, actual_symtab, 0x00000170,
			IMAGE_REL_I386_DIR32, "_NUM_ASCII_PROPERTIES");
		assertRel(actual_rel_text, actual_symtab, 0x00000176,
			IMAGE_REL_I386_DIR32, "_s_ascii_properties");
		assertRel(actual_rel_text, actual_symtab, 0x00000180,
			IMAGE_REL_I386_REL32, "_print_ascii_entry");
		assertRel(actual_rel_text, actual_symtab, 0x0000018d,
			IMAGE_REL_I386_DIR32, "_COLUMNS");
		assertRel(actual_rel_text, actual_symtab, 0x00000192,
			IMAGE_REL_I386_DIR32, "_COLUMNS");
		assertRel(actual_rel_text, actual_symtab, 0x000001b2,
			IMAGE_REL_I386_REL32, "_putchar");
		assertEquals(19, actual_rel_text.size());

		// .rdata relocations.
		assertRel(actual_rel_rdata, actual_symtab, 0x00000008,
			IMAGE_REL_I386_DIR32, "_openbsd_isgraph");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000010,
			IMAGE_REL_I386_DIR32, "_openbsd_isprint");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000018,
			IMAGE_REL_I386_DIR32, "_openbsd_iscntrl");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000020,
			IMAGE_REL_I386_DIR32, "_openbsd_isspace");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000028,
			IMAGE_REL_I386_DIR32, "_openbsd_ispunct");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000030,
			IMAGE_REL_I386_DIR32, "_openbsd_isalnum");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000038,
			IMAGE_REL_I386_DIR32, "_openbsd_isalpha");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000040,
			IMAGE_REL_I386_DIR32, "_openbsd_isdigit");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000048,
			IMAGE_REL_I386_DIR32, "_openbsd_isupper");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000050,
			IMAGE_REL_I386_DIR32, "_openbsd_islower");
		assertEquals(10, actual_rel_rdata.size());

		// Section bytes.
		assertSectionBytes(expected_text, actual_text);
		assertSectionBytes(expected_rdata, actual_rdata);
		assertSectionBytes(expected_data, actual_data);
	}

	@Test
	public void test_openbsd_ctype_obj() throws Exception {
		// Expected file.
		CoffFile expected = new CoffFile.Parser(new FileInputStream(openbsd_ctype_file)).parse();

		CoffSectionTable expectedSections = expected.getSections();
		var expected_text = findSectionByName(expectedSections, ".text$mn", CoffBytes.class);
		var expected_rdata = findSectionByName(expectedSections, ".rdata", CoffBytes.class);

		// Actual file.
		AddressSetView set = findProgramModule("Object Files", "openbsd_ctype.obj");
		File exportedFile = exportObjectFile(set, new CoffRelocatableObjectExporter(), null);
		CoffFile actual = new CoffFile.Parser(new FileInputStream(exportedFile)).parse();

		// COFF header.
		assertHeader(actual.getHeader(), CoffMachine.IMAGE_FILE_MACHINE_I386);

		CoffSectionTable actualSections = actual.getSections();
		var actual_text = findSectionByName(actualSections, ".text", CoffBytes.class);
		var actual_rdata = findSectionByName(actualSections, ".rdata", CoffBytes.class);

		CoffRelocationTable actual_rel_text = actual_text.getRelocations();
		CoffSymbolTable actual_symtab = actual.getSymbols();

		short actual_text_index = sectionNumber(actualSections, actual_text);
		short actual_rdata_index = sectionNumber(actualSections, actual_rdata);

		// Section flags.
		assertTrue(actual_text.getCharacteristics().isCntCode());
		assertTrue(actual_text.getCharacteristics().isMemExecute());
		assertTrue(actual_text.getCharacteristics().isMemRead());
		assertFalse(actual_text.getCharacteristics().isMemWrite());

		assertTrue(actual_rdata.getCharacteristics().isCntInitializedData());
		assertTrue(actual_rdata.getCharacteristics().isMemRead());
		assertFalse(actual_rdata.getCharacteristics().isMemExecute());
		assertFalse(actual_rdata.getCharacteristics().isMemWrite());

		// Defined symbols.
		assertSymbol(actual_symtab, actual_text_index, 0x00000000, "_openbsd_isalnum",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000030, "_openbsd_isalpha",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000060, "_openbsd_iscntrl",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000090, "_openbsd_isdigit",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_text_index, 0x000000c0, "_openbsd_isgraph",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_text_index, 0x000000f0, "_openbsd_islower",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000120, "_openbsd_isprint",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000150, "_openbsd_ispunct",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000180, "_openbsd_isspace",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_text_index, 0x000001b0, "_openbsd_isupper",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_text_index, 0x000001e0, "_openbsd_isxdigit",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_rdata_index, 0x00000000, "__openbsd_ctype_",
			IMAGE_SYM_CLASS_EXTERNAL);

		// .text relocations.
		assertRel(actual_rel_text, actual_symtab, 0x0000001a,
			IMAGE_REL_I386_DIR32, "__openbsd_ctype_");
		assertRel(actual_rel_text, actual_symtab, 0x0000004a,
			IMAGE_REL_I386_DIR32, "__openbsd_ctype_");
		assertRel(actual_rel_text, actual_symtab, 0x0000007a,
			IMAGE_REL_I386_DIR32, "__openbsd_ctype_");
		assertRel(actual_rel_text, actual_symtab, 0x000000aa,
			IMAGE_REL_I386_DIR32, "__openbsd_ctype_");
		assertRel(actual_rel_text, actual_symtab, 0x000000da,
			IMAGE_REL_I386_DIR32, "__openbsd_ctype_");
		assertRel(actual_rel_text, actual_symtab, 0x0000010a,
			IMAGE_REL_I386_DIR32, "__openbsd_ctype_");
		assertRel(actual_rel_text, actual_symtab, 0x0000013a,
			IMAGE_REL_I386_DIR32, "__openbsd_ctype_");
		assertRel(actual_rel_text, actual_symtab, 0x0000016a,
			IMAGE_REL_I386_DIR32, "__openbsd_ctype_");
		assertRel(actual_rel_text, actual_symtab, 0x0000019a,
			IMAGE_REL_I386_DIR32, "__openbsd_ctype_");
		assertRel(actual_rel_text, actual_symtab, 0x000001ca,
			IMAGE_REL_I386_DIR32, "__openbsd_ctype_");
		assertRel(actual_rel_text, actual_symtab, 0x000001fa,
			IMAGE_REL_I386_DIR32, "__openbsd_ctype_");
		assertEquals(11, actual_rel_text.size());

		// Section bytes.
		assertSectionBytes(expected_text, actual_text);
		assertSectionBytes(expected_rdata, actual_rdata);
	}
}
