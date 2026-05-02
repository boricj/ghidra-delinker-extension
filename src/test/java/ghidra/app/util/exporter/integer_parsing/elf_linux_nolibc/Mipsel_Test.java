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
package ghidra.app.util.exporter.integer_parsing.elf_linux_nolibc;

import static net.boricj.bft.elf.ElfSection.SHN_UNDEF;
import static net.boricj.bft.elf.constants.ElfClass.ELFCLASS32;
import static net.boricj.bft.elf.constants.ElfData.ELFDATA2LSB;
import static net.boricj.bft.elf.constants.ElfMachine.EM_MIPS;
import static net.boricj.bft.elf.constants.ElfSectionNames._REL;
import static net.boricj.bft.elf.constants.ElfSectionNames._RODATA;
import static net.boricj.bft.elf.constants.ElfSectionNames._SYMTAB;
import static net.boricj.bft.elf.constants.ElfSectionNames._TEXT;
import static net.boricj.bft.elf.constants.ElfSymbolBinding.STB_GLOBAL;
import static net.boricj.bft.elf.constants.ElfSymbolBinding.STB_LOCAL;
import static net.boricj.bft.elf.constants.ElfSymbolType.STT_FUNC;
import static net.boricj.bft.elf.constants.ElfSymbolType.STT_NOTYPE;
import static net.boricj.bft.elf.constants.ElfSymbolType.STT_OBJECT;
import static net.boricj.bft.elf.constants.ElfSymbolType.STT_SECTION;
import static net.boricj.bft.elf.constants.ElfSymbolVisibility.STV_DEFAULT;
import static net.boricj.bft.elf.constants.ElfType.ET_REL;
import static net.boricj.bft.elf.machines.mips.ElfRelocationType_Mips.R_MIPS_26;
import static net.boricj.bft.elf.machines.mips.ElfRelocationType_Mips.R_MIPS_32;
import static net.boricj.bft.elf.machines.mips.ElfRelocationType_Mips.R_MIPS_HI16;
import static net.boricj.bft.elf.machines.mips.ElfRelocationType_Mips.R_MIPS_LO16;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;

import org.junit.Test;

import ghidra.DelinkerIntegrationTest;
import ghidra.app.util.exporter.ElfRelocatableObjectExporter;
import ghidra.program.model.address.AddressSetView;
import net.boricj.bft.elf.ElfFile;
import net.boricj.bft.elf.ElfHeader;
import net.boricj.bft.elf.ElfSectionTable;
import net.boricj.bft.elf.sections.ElfProgBits;
import net.boricj.bft.elf.sections.ElfRelTable;
import net.boricj.bft.elf.sections.ElfSymbolTable;

public class Mipsel_Test extends DelinkerIntegrationTest {

	private static final File main_file = new File(
		"src/test/resources/programs/integer-parsing/reference/elf/linux-nolibc/mipsel/main.o");

	@Override
	protected String getProgramName() {
		return "src/test/resources/programs/integer-parsing/reference/elf/linux-nolibc/mipsel/integer-parsing.elf.gzf";
	}

	@Test
	public void test_main_o() throws Exception {
		// Expected file.
		ElfFile expected =
			new ElfFile.Parser(new FileInputStream(main_file)).setIgnoreSectionErrors(true).parse();

		ElfSectionTable expectedSections = expected.getSections();
		var expected_text = findSectionByName(expectedSections, _TEXT, ElfProgBits.class);
		var expected_rodata = findSectionByName(expectedSections, _RODATA, ElfProgBits.class);
		var expected_rodata_str1_4 =
			findSectionByName(expectedSections, _RODATA + ".str1.4", ElfProgBits.class);

		// Actual file.
		AddressSetView set = findProgramModule("Object Files", "main.o");
		File exportedFile = exportObjectFile(set, new ElfRelocatableObjectExporter(), null);
		ElfFile actual = new ElfFile.Parser(new FileInputStream(exportedFile)).parse();

		// ELF header.
		ElfHeader actualHeader = actual.getHeader();
		assertHeader(actualHeader, ELFCLASS32, ELFDATA2LSB, ET_REL, EM_MIPS);

		ElfSectionTable actualSections = actual.getSections();
		var actual_symtab = findSectionByName(actualSections, _SYMTAB, ElfSymbolTable.class);
		var actual_text = findSectionByName(actualSections, _TEXT, ElfProgBits.class);
		var actual_rel_text = findSectionByName(actualSections, _REL + _TEXT, ElfRelTable.class);
		var actual_rodata = findSectionByName(actualSections, _RODATA, ElfProgBits.class);
		var actual_rel_rodata =
			findSectionByName(actualSections, _REL + _RODATA, ElfRelTable.class);

		int actual_text_index = sectionNumber(actualSections, actual_text);
		int actual_rodata_index = sectionNumber(actualSections, actual_rodata);

		// .text section flags.
		assertTrue(actual_text.getFlags().isAlloc());
		assertFalse(actual_text.getFlags().isWrite());
		assertTrue(actual_text.getFlags().isExecInstr());

		// .rodata section flags.
		assertTrue(actual_rodata.getFlags().isAlloc());
		assertFalse(actual_rodata.getFlags().isWrite());
		assertFalse(actual_rodata.getFlags().isExecInstr());

		// .text symbols.
		assertSymbol(actual_symtab, actual_text_index, 0x00000000, 0,
			STT_SECTION, STV_DEFAULT, STB_LOCAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000000, "parse_decimal", 0x90,
			STT_FUNC, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000090, "main", 0xb8,
			STT_FUNC, STV_DEFAULT, STB_GLOBAL);

		// .rodata symbols.
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000000, 0,
			STT_SECTION, STV_DEFAULT, STB_LOCAL);
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000000, "s_ascii_digit_bias", 4,
			STT_OBJECT, STV_DEFAULT, STB_GLOBAL);

		// Undefined symbols.
		assertSymbol(actual_symtab, SHN_UNDEF, 0x00000000, "puts", 0,
			STT_NOTYPE, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, SHN_UNDEF, 0x00000000, "s_digits", 0,
			STT_NOTYPE, STV_DEFAULT, STB_GLOBAL);

		// .text relocations.
		assertRels(actual_rel_text,
			new Rel(0x00000034, R_MIPS_HI16, "s_digits"),
			new Rel(0x00000038, R_MIPS_LO16, "s_digits"));
		assertRels(actual_rel_text,
			new Rel(0x000000a0, R_MIPS_HI16, "s_0_00408d68"),
			new Rel(0x000000a4, R_MIPS_LO16, "s_0_00408d68"));
		assertRel(actual_rel_text, 0x000000a8, R_MIPS_26, "parse_decimal");
		assertRels(actual_rel_text,
			new Rel(0x000000c4, R_MIPS_HI16, "s_123_00408dd0"),
			new Rel(0x000000c8, R_MIPS_LO16, "s_123_00408dd0"));
		assertRel(actual_rel_text, 0x000000cc, R_MIPS_26, "parse_decimal");
		assertRels(actual_rel_text,
			new Rel(0x000000f0, R_MIPS_HI16, "s_65535_00408dd4"),
			new Rel(0x000000f4, R_MIPS_LO16, "s_65535_00408dd4"));
		assertRel(actual_rel_text, 0x000000f8, R_MIPS_26, "parse_decimal");
		assertRels(actual_rel_text,
			new Rel(0x0000011c, R_MIPS_HI16, "s_All_tests_passed._00408ddc"),
			new Rel(0x00000120, R_MIPS_LO16, "s_All_tests_passed._00408ddc"));
		assertRel(actual_rel_text, 0x00000124, R_MIPS_26, "puts");
		assertEquals(14, actual_rel_text.size());

		// .rodata relocations.
		assertRel(actual_rel_rodata, 0x00000000, R_MIPS_32, "s_digits");
		assertEquals(1, actual_rel_rodata.size());

		// .text bytes.
		assertSectionBytes(expected_text, 0x8834, actual_text, 0, actual_text.getBytes().length,
			new Patch(0x00000124, new byte[] { 0x00, 0x00, 0x00, 0x0c }));

		// .rodata bytes.
		assertSectionBytes(expected_rodata, 0x00000028,
			actual_rodata, 0x00000000, 0x8);
		assertSectionBytes(expected_rodata_str1_4, 0x0000000c,
			actual_rodata, 0x00000008, 0x4);
		assertSectionBytes(expected_rodata_str1_4, 0x00000074,
			actual_rodata, 0x0000000c, 0x20);
	}
}
