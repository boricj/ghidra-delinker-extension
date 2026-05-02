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
package ghidra.app.util.exporter.ascii_table.elf_linux_nolibc;

import static net.boricj.bft.elf.constants.ElfClass.ELFCLASS32;
import static net.boricj.bft.elf.constants.ElfData.ELFDATA2LSB;
import static net.boricj.bft.elf.constants.ElfMachine.EM_386;
import static net.boricj.bft.elf.constants.ElfType.ET_REL;
import static net.boricj.bft.elf.ElfSection.SHN_UNDEF;
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
import static net.boricj.bft.elf.machines.i386.ElfRelocationType_i386.R_386_32;
import static net.boricj.bft.elf.machines.i386.ElfRelocationType_i386.R_386_PC32;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

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

public class I686_Test extends DelinkerIntegrationTest {
	private static final File main_file =
		new File("src/test/resources/programs/ascii-table/reference/elf/linux-nolibc/i686/main.o");

	private static final File openbsd_ctype_file =
		new File(
			"src/test/resources/programs/ascii-table/reference/elf/linux-nolibc/i686/openbsd_ctype.o");

	@Override
	protected String getProgramName() {
		return "src/test/resources/programs/ascii-table/reference/elf/linux-nolibc/i686/ascii-table.elf.gzf";
	}

	@Test
	public void test_main_o() throws Exception {
		// Expected file.
		ElfFile expected = new ElfFile.Parser(new FileInputStream(main_file)).parse();

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
		assertHeader(actualHeader, ELFCLASS32, ELFDATA2LSB, ET_REL, EM_386);

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
		assertSymbol(actual_symtab, actual_text_index, 0x00000000, "print_number", 98, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000062, "print_ascii_entry", 201,
			STT_FUNC, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x0000012b, "main", 188, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);

		// .rodata symbols.
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000000, 0, STT_SECTION, STV_DEFAULT,
			STB_LOCAL);
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000000, "NUM_ASCII_PROPERTIES", 4,
			STT_OBJECT, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000010, "s_ascii_properties", 80,
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

		// .text relocations.
		assertRel(actual_rel_text, 0x0000003c, R_386_PC32, "putchar");
		assertRel(actual_rel_text, 0x0000004d, R_386_PC32, "putchar");
		assertRel(actual_rel_text, 0x0000007e, R_386_PC32, "putchar");
		assertRel(actual_rel_text, 0x0000008e, R_386_PC32, "openbsd_isgraph");
		assertRel(actual_rel_text, 0x000000a2, R_386_PC32, "putchar");
		assertRel(actual_rel_text, 0x000000b1, R_386_PC32, "putchar");
		assertRel(actual_rel_text, 0x000000be, R_386_PC32, "putchar");
		assertRel(actual_rel_text, 0x00000105, R_386_PC32, "putchar");
		assertRel(actual_rel_text, 0x00000114, R_386_PC32, "putchar");
		assertRel(actual_rel_text, 0x0000014a, R_386_32, "COLUMNS");
		assertRel(actual_rel_text, 0x00000159, R_386_32, "COLUMNS");
		assertRel(actual_rel_text, 0x0000016e, R_386_32, "COLUMNS");
		assertRel(actual_rel_text, 0x0000018f, R_386_32, "s_ascii_properties");
		assertRel(actual_rel_text, 0x0000019e, R_386_32, "COLUMNS");
		assertRel(actual_rel_text, 0x000001a9, R_386_32, "COLUMNS");
		assertRel(actual_rel_text, 0x000001c5, R_386_PC32, "putchar");
		assertEquals(16, actual_rel_text.size());

		// .rodata relocations.
		assertRel(actual_rel_rodata, 0x00000010, R_386_32, "openbsd_isgraph");
		assertRel(actual_rel_rodata, 0x00000018, R_386_32, "openbsd_isprint");
		assertRel(actual_rel_rodata, 0x00000020, R_386_32, "openbsd_iscntrl");
		assertRel(actual_rel_rodata, 0x00000028, R_386_32, "openbsd_isspace");
		assertRel(actual_rel_rodata, 0x00000030, R_386_32, "openbsd_ispunct");
		assertRel(actual_rel_rodata, 0x00000038, R_386_32, "openbsd_isalnum");
		assertRel(actual_rel_rodata, 0x00000040, R_386_32, "openbsd_isalpha");
		assertRel(actual_rel_rodata, 0x00000048, R_386_32, "openbsd_isdigit");
		assertRel(actual_rel_rodata, 0x00000050, R_386_32, "openbsd_isupper");
		assertRel(actual_rel_rodata, 0x00000058, R_386_32, "openbsd_islower");
		assertEquals(10, actual_rel_rodata.size());

		// .text bytes.
		assertSectionBytes(expected_text, 0x00004078, actual_text, 0x00000000, 0x0001e7,
			new Patch(0x0000003c,
				new byte[] { (byte) 0xfc, (byte) 0xff, (byte) 0xff, (byte) 0xff }),
			new Patch(0x0000004d,
				new byte[] { (byte) 0xfc, (byte) 0xff, (byte) 0xff, (byte) 0xff }),
			new Patch(0x00000074,
				new byte[] { (byte) 0x88, (byte) 0xff, (byte) 0xff, (byte) 0xff }),
			new Patch(0x0000007e,
				new byte[] { (byte) 0xfc, (byte) 0xff, (byte) 0xff, (byte) 0xff }),
			new Patch(0x000000a2,
				new byte[] { (byte) 0xfc, (byte) 0xff, (byte) 0xff, (byte) 0xff }),
			new Patch(0x000000b1,
				new byte[] { (byte) 0xfc, (byte) 0xff, (byte) 0xff, (byte) 0xff }),
			new Patch(0x000000be,
				new byte[] { (byte) 0xfc, (byte) 0xff, (byte) 0xff, (byte) 0xff }),
			new Patch(0x00000105,
				new byte[] { (byte) 0xfc, (byte) 0xff, (byte) 0xff, (byte) 0xff }),
			new Patch(0x00000114,
				new byte[] { (byte) 0xfc, (byte) 0xff, (byte) 0xff, (byte) 0xff }),
			new Patch(0x00000195,
				new byte[] { (byte) 0xc9, (byte) 0xfe, (byte) 0xff, (byte) 0xff }),
			new Patch(0x000001c5,
				new byte[] { (byte) 0xfc, (byte) 0xff, (byte) 0xff, (byte) 0xff }));

		// .rodata bytes.
		assertSectionBytes(expected_rodata, 0x00000090,
			actual_rodata, 0x00000000, 0x60);

		// .data bytes.
		assertSectionBytes(expected_data, 0x00000000,
			actual_data, 0x00000000, 0x4);
	}

	@Test
	public void test_openbsd_ctype_o() throws Exception {
		// Expected file.
		ElfFile expected = new ElfFile.Parser(new FileInputStream(openbsd_ctype_file)).parse();

		ElfSectionTable expectedSections = expected.getSections();
		var expected_text = findSectionByName(expectedSections, _TEXT, ElfProgBits.class);
		var expected_rodata = findSectionByName(expectedSections, _RODATA, ElfProgBits.class);

		// Actual file.
		AddressSetView set = findProgramModule("Object Files", "openbsd_ctype.o");
		File exportedFile = exportObjectFile(set, new ElfRelocatableObjectExporter(), null);
		ElfFile actual = new ElfFile.Parser(new FileInputStream(exportedFile)).parse();

		// ELF header.
		ElfHeader actualHeader = actual.getHeader();
		assertHeader(actualHeader, ELFCLASS32, ELFDATA2LSB, ET_REL, EM_386);

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
		assertSymbol(actual_symtab, actual_text_index, 0x00000000, "openbsd_isalnum", 41, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000029, "openbsd_isalpha", 41, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000052, "openbsd_iscntrl", 41, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x0000007b, "openbsd_isdigit", 41, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x000000a4, "openbsd_isgraph", 41, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x000000cd, "openbsd_islower", 41, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x000000f6, "openbsd_isprint", 43, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000121, "openbsd_ispunct", 41, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x0000014a, "openbsd_isspace", 41, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000173, "openbsd_isupper", 41, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x0000019c, "openbsd_isxdigit", 41, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);

		// .rodata symbols.
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000000, 0, STT_SECTION, STV_DEFAULT,
			STB_LOCAL);
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000000, "_openbsd_ctype_", 257,
			STT_OBJECT, STV_DEFAULT, STB_GLOBAL);

		// .rel.text relocations.
		assertRel(actual_rel_text, 0x00000013, R_386_32, "_openbsd_ctype_");
		assertRel(actual_rel_text, 0x0000003c, R_386_32, "_openbsd_ctype_");
		assertRel(actual_rel_text, 0x00000065, R_386_32, "_openbsd_ctype_");
		assertRel(actual_rel_text, 0x0000008e, R_386_32, "_openbsd_ctype_");
		assertRel(actual_rel_text, 0x000000b7, R_386_32, "_openbsd_ctype_");
		assertRel(actual_rel_text, 0x000000e0, R_386_32, "_openbsd_ctype_");
		assertRel(actual_rel_text, 0x00000109, R_386_32, "_openbsd_ctype_");
		assertRel(actual_rel_text, 0x00000134, R_386_32, "_openbsd_ctype_");
		assertRel(actual_rel_text, 0x0000015d, R_386_32, "_openbsd_ctype_");
		assertRel(actual_rel_text, 0x00000186, R_386_32, "_openbsd_ctype_");
		assertRel(actual_rel_text, 0x000001af, R_386_32, "_openbsd_ctype_");
		assertEquals(11, actual_rel_text.size());

		// .text bytes.
		assertSectionBytes(expected_text, actual_text);

		// .rodata bytes.
		assertSectionBytes(expected_rodata, actual_rodata);
	}
}
