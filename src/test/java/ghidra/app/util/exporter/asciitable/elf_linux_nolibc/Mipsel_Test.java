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
package ghidra.app.util.exporter.asciitable.elf_linux_nolibc;

import static net.boricj.bft.elf.ElfSection.SHN_UNDEF;
import static net.boricj.bft.elf.constants.ElfClass.ELFCLASS32;
import static net.boricj.bft.elf.constants.ElfData.ELFDATA2LSB;
import static net.boricj.bft.elf.constants.ElfMachine.EM_MIPS;
import static net.boricj.bft.elf.constants.ElfSectionNames._DATA;
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
	private static final File main_file =
		new File(
			"src/test/resources/programs/ascii-table/reference/elf/linux-nolibc/mipsel/main.o");

	private static final File openbsd_ctype_file =
		new File(
			"src/test/resources/programs/ascii-table/reference/elf/linux-nolibc/mipsel/openbsd_ctype.o");

	@Override
	protected String getProgramName() {
		return "src/test/resources/programs/ascii-table/reference/elf/linux-nolibc/mipsel/ascii-table.elf.gzf";
	}

	@Test
	public void test_main_o() throws Exception {
		// Expected file.
		ElfFile expected =
			new ElfFile.Parser(new FileInputStream(main_file)).setIgnoreSectionErrors(true).parse();

		ElfSectionTable expectedSections = expected.getSections();
		var expected_text = findSectionByName(expectedSections, _TEXT, ElfProgBits.class);
		var expected_rodata = findSectionByName(expectedSections, _RODATA, ElfProgBits.class);
		var expected_data = findSectionByName(expectedSections, _DATA, ElfProgBits.class);

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
		var actual_data = findSectionByName(actualSections, _DATA, ElfProgBits.class);

		int actual_text_index = sectionNumber(actualSections, actual_text);
		int actual_rodata_index = sectionNumber(actualSections, actual_rodata);
		int actual_data_index = sectionNumber(actualSections, actual_data);

		// .text section.
		assertTrue(actual_text.getFlags().isAlloc());
		assertFalse(actual_text.getFlags().isWrite());
		assertTrue(actual_text.getFlags().isExecInstr());

		// .rodata section.
		assertTrue(actual_rodata.getFlags().isAlloc());
		assertFalse(actual_rodata.getFlags().isWrite());
		assertFalse(actual_rodata.getFlags().isExecInstr());

		// .data section.
		assertTrue(actual_data.getFlags().isAlloc());
		assertTrue(actual_data.getFlags().isWrite());
		assertFalse(actual_data.getFlags().isExecInstr());

		// .text symbols.
		assertSymbol(actual_symtab, actual_text_index, 0x00000000, 0, STT_SECTION, STV_DEFAULT,
			STB_LOCAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000000, "print_number", 212, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x000000d4, "print_ascii_entry", 300,
			STT_FUNC, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000200, "main", 284, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);

		// .rodata symbols.
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000000, 0, STT_SECTION, STV_DEFAULT,
			STB_LOCAL);
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000000, "NUM_ASCII_PROPERTIES", 4,
			STT_OBJECT, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000004, "s_ascii_properties", 80,
			STT_OBJECT, STV_DEFAULT, STB_GLOBAL);

		// .data symbols.
		assertSymbol(actual_symtab, actual_data_index, 0x00000000, 0, STT_SECTION, STV_DEFAULT,
			STB_LOCAL);
		assertSymbol(actual_symtab, actual_data_index, 0x00000000, "COLUMNS", 4, STT_OBJECT,
			STV_DEFAULT, STB_GLOBAL);

		// Undefined symbols.
		assertSymbol(actual_symtab, SHN_UNDEF, 0x00000000, "openbsd_isgraph", 0, STT_NOTYPE,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, SHN_UNDEF, 0x00000000, "openbsd_isprint", 0, STT_NOTYPE,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, SHN_UNDEF, 0x00000000, "openbsd_iscntrl", 0, STT_NOTYPE,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, SHN_UNDEF, 0x00000000, "openbsd_isspace", 0, STT_NOTYPE,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, SHN_UNDEF, 0x00000000, "openbsd_ispunct", 0, STT_NOTYPE,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, SHN_UNDEF, 0x00000000, "openbsd_isalnum", 0, STT_NOTYPE,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, SHN_UNDEF, 0x00000000, "openbsd_isalpha", 0, STT_NOTYPE,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, SHN_UNDEF, 0x00000000, "openbsd_isdigit", 0, STT_NOTYPE,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, SHN_UNDEF, 0x00000000, "openbsd_isupper", 0, STT_NOTYPE,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, SHN_UNDEF, 0x00000000, "openbsd_islower", 0, STT_NOTYPE,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, SHN_UNDEF, 0x00000000, "putchar", 0, STT_NOTYPE,
			STV_DEFAULT, STB_GLOBAL);

		assertRel(actual_rel_text, 0x00000078, R_MIPS_26, "putchar");
		assertRel(actual_rel_text, 0x00000094, R_MIPS_26, "putchar");
		assertRel(actual_rel_text, 0x000000fc, R_MIPS_26, "print_number");
		assertRel(actual_rel_text, 0x00000108, R_MIPS_26, "putchar");
		assertRel(actual_rel_text, 0x00000118, R_MIPS_26, "openbsd_isgraph");
		assertRel(actual_rel_text, 0x00000130, R_MIPS_26, "putchar");
		assertRel(actual_rel_text, 0x00000144, R_MIPS_26, "putchar");
		assertRel(actual_rel_text, 0x00000150, R_MIPS_26, "putchar");
		assertRel(actual_rel_text, 0x000001a4, R_MIPS_26, "putchar");
		assertRel(actual_rel_text, 0x000001b8, R_MIPS_26, "putchar");
		assertRels(actual_rel_text,
			new Rel(0x0000021c, R_MIPS_HI16, "COLUMNS"),
			new Rel(0x00000220, R_MIPS_LO16, "COLUMNS"));
		assertRels(actual_rel_text,
			new Rel(0x00000234, R_MIPS_HI16, "COLUMNS"),
			new Rel(0x00000238, R_MIPS_LO16, "COLUMNS"));
		assertRels(actual_rel_text,
			new Rel(0x00000258, R_MIPS_HI16, "COLUMNS"),
			new Rel(0x0000025c, R_MIPS_LO16, "COLUMNS"));
		assertRels(actual_rel_text,
			new Rel(0x00000288, R_MIPS_HI16, "s_ascii_properties"),
			new Rel(0x0000028c, R_MIPS_LO16, "s_ascii_properties"));
		assertRel(actual_rel_text, 0x00000294, R_MIPS_26, "print_ascii_entry");
		assertRels(actual_rel_text,
			new Rel(0x0000029c, R_MIPS_HI16, "COLUMNS"),
			new Rel(0x000002a0, R_MIPS_LO16, "COLUMNS"));
		assertRels(actual_rel_text,
			new Rel(0x000002b4, R_MIPS_HI16, "COLUMNS"),
			new Rel(0x000002b8, R_MIPS_LO16, "COLUMNS"));
		assertRel(actual_rel_text, 0x000002dc, R_MIPS_26, "putchar");
		assertEquals(24, actual_rel_text.size());

		// .rodata relocations.
		assertRel(actual_rel_rodata, 0x00000004, R_MIPS_32, "openbsd_isgraph");
		assertRel(actual_rel_rodata, 0x0000000c, R_MIPS_32, "openbsd_isprint");
		assertRel(actual_rel_rodata, 0x00000014, R_MIPS_32, "openbsd_iscntrl");
		assertRel(actual_rel_rodata, 0x0000001c, R_MIPS_32, "openbsd_isspace");
		assertRel(actual_rel_rodata, 0x00000024, R_MIPS_32, "openbsd_ispunct");
		assertRel(actual_rel_rodata, 0x0000002c, R_MIPS_32, "openbsd_isalnum");
		assertRel(actual_rel_rodata, 0x00000034, R_MIPS_32, "openbsd_isalpha");
		assertRel(actual_rel_rodata, 0x0000003c, R_MIPS_32, "openbsd_isdigit");
		assertRel(actual_rel_rodata, 0x00000044, R_MIPS_32, "openbsd_isupper");
		assertRel(actual_rel_rodata, 0x0000004c, R_MIPS_32, "openbsd_islower");
		assertEquals(10, actual_rel_rodata.size());

		// .text bytes.
		assertSectionBytes(expected_text, 0x00008834, actual_text, 0x00000000, 0x00031c,
			new Patch(0x00000078, new byte[] { 0x00, 0x00, 0x00, 0x0c }),
			new Patch(0x00000094, new byte[] { 0x00, 0x00, 0x00, 0x0c }),
			new Patch(0x000000fc, new byte[] { 0x00, 0x00, 0x00, 0x0c }),
			new Patch(0x00000108, new byte[] { 0x00, 0x00, 0x00, 0x0c }),
			new Patch(0x00000118, new byte[] { 0x00, 0x00, 0x00, 0x0c }),
			new Patch(0x00000130, new byte[] { 0x00, 0x00, 0x00, 0x0c }),
			new Patch(0x00000144, new byte[] { 0x00, 0x00, 0x00, 0x0c }),
			new Patch(0x00000150, new byte[] { 0x00, 0x00, 0x00, 0x0c }),
			new Patch(0x000001a4, new byte[] { 0x00, 0x00, 0x00, 0x0c }),
			new Patch(0x000001b8, new byte[] { 0x00, 0x00, 0x00, 0x0c }),
			new Patch(0x0000021c, new byte[] { 0x00, 0x00 }),
			new Patch(0x00000220, new byte[] { 0x00, 0x00 }),
			new Patch(0x00000234, new byte[] { 0x00, 0x00 }),
			new Patch(0x00000238, new byte[] { 0x00, 0x00 }),
			new Patch(0x00000258, new byte[] { 0x00, 0x00 }),
			new Patch(0x0000025c, new byte[] { 0x00, 0x00 }),
			new Patch(0x00000288, new byte[] { 0x00, 0x00 }),
			new Patch(0x0000028c, new byte[] { 0x00, 0x00 }),
			new Patch(0x00000294, new byte[] { 0x00, 0x00, 0x00, 0x0c }),
			new Patch(0x0000029c, new byte[] { 0x00, 0x00 }),
			new Patch(0x000002a0, new byte[] { 0x00, 0x00 }),
			new Patch(0x000002b4, new byte[] { 0x00, 0x00 }),
			new Patch(0x000002b8, new byte[] { 0x00, 0x00 }),
			new Patch(0x000002dc, new byte[] { 0x00, 0x00, 0x00, 0x0c }));

		// .rodata bytes.
		assertSectionBytes(expected_rodata, 0x00000028,
			actual_rodata, 0x00000000, 0x54);

		// .data bytes.
		assertSectionBytes(expected_data, 0x00000000,
			actual_data, 0x00000000, 0x4);
	}

	@Test
	public void test_openbsd_ctype_o() throws Exception {
		// Expected file.
		ElfFile expected =
			new ElfFile.Parser(new FileInputStream(openbsd_ctype_file)).setIgnoreSectionErrors(true)
					.parse();

		ElfSectionTable expectedSections = expected.getSections();
		var expected_text = findSectionByName(expectedSections, _TEXT, ElfProgBits.class);
		var expected_rodata = findSectionByName(expectedSections, _RODATA, ElfProgBits.class);

		// Actual file.
		AddressSetView set = findProgramModule("Object Files", "openbsd_ctype.o");
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

		int actual_text_index = sectionNumber(actualSections, actual_text);
		int actual_rodata_index = sectionNumber(actualSections, actual_rodata);

		// .text section.
		assertTrue(actual_text.getFlags().isAlloc());
		assertFalse(actual_text.getFlags().isWrite());
		assertTrue(actual_text.getFlags().isExecInstr());

		// .rodata section.
		assertTrue(actual_rodata.getFlags().isAlloc());
		assertFalse(actual_rodata.getFlags().isWrite());
		assertFalse(actual_rodata.getFlags().isExecInstr());

		// .text symbols.
		assertSymbol(actual_symtab, actual_text_index, 0x00000000, 0, STT_SECTION, STV_DEFAULT,
			STB_LOCAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000000, "openbsd_isalnum", 100, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000064, "openbsd_isalpha", 100, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x000000c8, "openbsd_iscntrl", 100, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x0000012c, "openbsd_isdigit", 100, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000190, "openbsd_isgraph", 100, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x000001f4, "openbsd_islower", 100, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000258, "openbsd_isprint", 96, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x000002b8, "openbsd_ispunct", 100, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x0000031c, "openbsd_isspace", 100, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000380, "openbsd_isupper", 100, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x000003e4, "openbsd_isxdigit", 100,
			STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);

		// .rodata symbols.
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000000, 0, STT_SECTION, STV_DEFAULT,
			STB_LOCAL);
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000000, "_openbsd_ctype_", 257,
			STT_OBJECT, STV_DEFAULT, STB_GLOBAL);

		assertRels(actual_rel_text,
			new Rel(0x0000002c, R_MIPS_HI16, "_openbsd_ctype_"),
			new Rel(0x00000030, R_MIPS_LO16, "_openbsd_ctype_"));
		assertRels(actual_rel_text,
			new Rel(0x00000090, R_MIPS_HI16, "_openbsd_ctype_"),
			new Rel(0x00000094, R_MIPS_LO16, "_openbsd_ctype_"));
		assertRels(actual_rel_text,
			new Rel(0x000000f4, R_MIPS_HI16, "_openbsd_ctype_"),
			new Rel(0x000000f8, R_MIPS_LO16, "_openbsd_ctype_"));
		assertRels(actual_rel_text,
			new Rel(0x00000158, R_MIPS_HI16, "_openbsd_ctype_"),
			new Rel(0x0000015c, R_MIPS_LO16, "_openbsd_ctype_"));
		assertRels(actual_rel_text,
			new Rel(0x000001bc, R_MIPS_HI16, "_openbsd_ctype_"),
			new Rel(0x000001c0, R_MIPS_LO16, "_openbsd_ctype_"));
		assertRels(actual_rel_text,
			new Rel(0x00000220, R_MIPS_HI16, "_openbsd_ctype_"),
			new Rel(0x00000224, R_MIPS_LO16, "_openbsd_ctype_"));
		assertRels(actual_rel_text,
			new Rel(0x00000284, R_MIPS_HI16, "_openbsd_ctype_"),
			new Rel(0x00000288, R_MIPS_LO16, "_openbsd_ctype_"));
		assertRels(actual_rel_text,
			new Rel(0x000002e4, R_MIPS_HI16, "_openbsd_ctype_"),
			new Rel(0x000002e8, R_MIPS_LO16, "_openbsd_ctype_"));
		assertRels(actual_rel_text,
			new Rel(0x00000348, R_MIPS_HI16, "_openbsd_ctype_"),
			new Rel(0x0000034c, R_MIPS_LO16, "_openbsd_ctype_"));
		assertRels(actual_rel_text,
			new Rel(0x000003ac, R_MIPS_HI16, "_openbsd_ctype_"),
			new Rel(0x000003b0, R_MIPS_LO16, "_openbsd_ctype_"));
		assertRels(actual_rel_text,
			new Rel(0x00000410, R_MIPS_HI16, "_openbsd_ctype_"),
			new Rel(0x00000414, R_MIPS_LO16, "_openbsd_ctype_"));
		assertEquals(22, actual_rel_text.size());

		// .text bytes.
		assertSectionBytes(expected_text, actual_text);

		// .rodata bytes.
		assertSectionBytes(expected_rodata, actual_rodata);
	}
}