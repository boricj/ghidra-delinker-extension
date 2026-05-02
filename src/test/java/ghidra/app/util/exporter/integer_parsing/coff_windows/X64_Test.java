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
package ghidra.app.util.exporter.integer_parsing.coff_windows;

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

public class X64_Test extends DelinkerIntegrationTest {

	private static final File main_file = new File(
		"src/test/resources/programs/integer-parsing/reference/coff/windows-msvc/x64/main.obj");

	@Override
	protected String getProgramName() {
		return "src/test/resources/programs/integer-parsing/reference/coff/windows-msvc/x64/integer-parsing.exe.gzf";
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
		assertHeader(actual.getHeader(), CoffMachine.IMAGE_FILE_MACHINE_AMD64);

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
		assertSymbol(actual_symtab, actual_text_index, 0x00000000, ".text",
			IMAGE_SYM_CLASS_STATIC);
		assertSymbol(actual_symtab, actual_text_index, 0x00000000, "parse_decimal",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000060, "main",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_rdata_index, 0x00000000, ".rdata",
			IMAGE_SYM_CLASS_STATIC);
		assertSymbol(actual_symtab, actual_rdata_index, 0x00000000, "s_ascii_digit_bias",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_data_index, 0x00000000, ".data",
			IMAGE_SYM_CLASS_STATIC);
		assertSymbol(actual_symtab, actual_data_index, 0x00000000, "s_0_14009c000",
			IMAGE_SYM_CLASS_STATIC);
		assertSymbol(actual_symtab, actual_data_index, 0x00000004, "s_123_14009c004",
			IMAGE_SYM_CLASS_STATIC);
		assertSymbol(actual_symtab, actual_data_index, 0x00000008, "s_65535_14009c008",
			IMAGE_SYM_CLASS_STATIC);
		assertSymbol(actual_symtab, actual_data_index, 0x00000010, "s_All_tests_passed._14009c010",
			IMAGE_SYM_CLASS_STATIC);

		// Undefined symbols.
		assertUndefined(actual_symtab, "puts");
		assertUndefined(actual_symtab, "s_digits");

		// .text relocations.
		assertRel(actual_rel_text, actual_symtab, 0x0000002b,
			IMAGE_REL_AMD64_REL32, "s_ascii_digit_bias");
		assertRel(actual_rel_text, actual_symtab, 0x00000067,
			IMAGE_REL_AMD64_REL32, "s_0_14009c000");
		assertRel(actual_rel_text, actual_symtab, 0x0000006c,
			IMAGE_REL_AMD64_REL32, "parse_decimal");
		assertRel(actual_rel_text, actual_symtab, 0x0000007e,
			IMAGE_REL_AMD64_REL32, "s_123_14009c004");
		assertRel(actual_rel_text, actual_symtab, 0x00000083,
			IMAGE_REL_AMD64_REL32, "parse_decimal");
		assertRel(actual_rel_text, actual_symtab, 0x00000096,
			IMAGE_REL_AMD64_REL32, "s_65535_14009c008");
		assertRel(actual_rel_text, actual_symtab, 0x0000009b,
			IMAGE_REL_AMD64_REL32, "parse_decimal");
		assertRel(actual_rel_text, actual_symtab, 0x000000b0,
			IMAGE_REL_AMD64_REL32, "s_All_tests_passed._14009c010");
		assertRel(actual_rel_text, actual_symtab, 0x000000b5,
			IMAGE_REL_AMD64_REL32, "puts");
		assertEquals(9, actual_rel_text.size());

		// .rdata relocations.
		assertRel(actual_rel_rdata, actual_symtab, 0x00000000,
			IMAGE_REL_AMD64_ADDR64, "s_digits");
		assertEquals(1, actual_rel_rdata.size());

		// Section bytes.
		assertSectionBytes(expected_text, actual_text);
		assertSectionBytes(expected_rdata, actual_rdata);
		assertSectionBytes(expected_data, actual_data);
	}
}
