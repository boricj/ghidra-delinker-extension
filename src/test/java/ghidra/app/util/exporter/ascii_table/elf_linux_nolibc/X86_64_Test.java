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

import static net.boricj.bft.elf.ElfSection.SHN_UNDEF;
import static net.boricj.bft.elf.constants.ElfClass.ELFCLASS64;
import static net.boricj.bft.elf.constants.ElfData.ELFDATA2LSB;
import static net.boricj.bft.elf.constants.ElfMachine.EM_X86_64;
import static net.boricj.bft.elf.constants.ElfSectionNames._DATA;
import static net.boricj.bft.elf.constants.ElfSectionNames._RELA;
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
import static net.boricj.bft.elf.machines.amd64.ElfRelocationType_amd64.R_X86_64_32S;
import static net.boricj.bft.elf.machines.amd64.ElfRelocationType_amd64.R_X86_64_64;
import static net.boricj.bft.elf.machines.amd64.ElfRelocationType_amd64.R_X86_64_PC32;

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
import net.boricj.bft.elf.sections.ElfRelaTable;
import net.boricj.bft.elf.sections.ElfSymbolTable;

public class X86_64_Test extends DelinkerIntegrationTest {
	private static final File main_file =
		new File(
			"src/test/resources/programs/ascii-table/reference/elf/linux-nolibc/x86_64/main.o");

	private static final File openbsd_ctype_file =
		new File(
			"src/test/resources/programs/ascii-table/reference/elf/linux-nolibc/x86_64/openbsd_ctype.o");

	@Override
	protected String getProgramName() {
		return "src/test/resources/programs/ascii-table/reference/elf/linux-nolibc/x86_64/ascii-table.elf.gzf";
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
		assertHeader(actualHeader, ELFCLASS64, ELFDATA2LSB, ET_REL, EM_X86_64);

		ElfSectionTable actualSections = actual.getSections();
		var actual_symtab = findSectionByName(actualSections, _SYMTAB, ElfSymbolTable.class);
		var actual_text = findSectionByName(actualSections, _TEXT, ElfProgBits.class);
		var actual_rela_text = findSectionByName(actualSections, _RELA + _TEXT, ElfRelaTable.class);
		var actual_rodata = findSectionByName(actualSections, _RODATA, ElfProgBits.class);
		var actual_rela_rodata =
			findSectionByName(actualSections, _RELA + _RODATA, ElfRelaTable.class);
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
		assertSymbol(actual_symtab, actual_text_index, 0x00000000, "print_number", 99, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000063, "print_ascii_entry", 186,
			STT_FUNC, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x0000011d, "main", 160, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);

		// .rodata symbols.
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000000, 0, STT_SECTION, STV_DEFAULT,
			STB_LOCAL);
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000000, "NUM_ASCII_PROPERTIES", 4,
			STT_OBJECT, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000004, "s_ascii_properties", 160,
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
		assertRela(actual_rela_text, 0x000000000042, R_X86_64_PC32, "putchar", -4);
		assertRela(actual_rela_text, 0x000000000051, R_X86_64_PC32, "putchar", -4);
		assertRela(actual_rela_text, 0x000000000088, R_X86_64_PC32, "putchar", -4);
		assertRela(actual_rela_text, 0x000000000093, R_X86_64_PC32, "openbsd_isgraph", -4);
		assertRela(actual_rela_text, 0x0000000000a2, R_X86_64_PC32, "putchar", -4);
		assertRela(actual_rela_text, 0x0000000000ae, R_X86_64_PC32, "putchar", -4);
		assertRela(actual_rela_text, 0x0000000000b8, R_X86_64_PC32, "putchar", -4);
		assertRela(actual_rela_text, 0x0000000000fd, R_X86_64_PC32, "putchar", -4);
		assertRela(actual_rela_text, 0x000000000109, R_X86_64_PC32, "putchar", -4);
		assertRela(actual_rela_text, 0x000000000130, R_X86_64_PC32, "COLUMNS", -4);
		assertRela(actual_rela_text, 0x00000000013f, R_X86_64_PC32, "COLUMNS", -4);
		assertRela(actual_rela_text, 0x000000000154, R_X86_64_PC32, "COLUMNS", -4);
		assertRela(actual_rela_text, 0x000000000171, R_X86_64_32S, "s_ascii_properties", 0);
		assertRela(actual_rela_text, 0x00000000017e, R_X86_64_PC32, "COLUMNS", -4);
		assertRela(actual_rela_text, 0x00000000018a, R_X86_64_PC32, "COLUMNS", -4);
		assertRela(actual_rela_text, 0x0000000001a4, R_X86_64_PC32, "putchar", -4);
		assertEquals(16, actual_rela_text.size());

		// .rodata relocations.
		assertRela(actual_rela_rodata, 0x00000004, R_X86_64_64, "openbsd_isgraph", 0);
		assertRela(actual_rela_rodata, 0x00000014, R_X86_64_64, "openbsd_isprint", 0);
		assertRela(actual_rela_rodata, 0x00000024, R_X86_64_64, "openbsd_iscntrl", 0);
		assertRela(actual_rela_rodata, 0x00000034, R_X86_64_64, "openbsd_isspace", 0);
		assertRela(actual_rela_rodata, 0x00000044, R_X86_64_64, "openbsd_ispunct", 0);
		assertRela(actual_rela_rodata, 0x00000054, R_X86_64_64, "openbsd_isalnum", 0);
		assertRela(actual_rela_rodata, 0x00000064, R_X86_64_64, "openbsd_isalpha", 0);
		assertRela(actual_rela_rodata, 0x00000074, R_X86_64_64, "openbsd_isdigit", 0);
		assertRela(actual_rela_rodata, 0x00000084, R_X86_64_64, "openbsd_isupper", 0);
		assertRela(actual_rela_rodata, 0x00000094, R_X86_64_64, "openbsd_islower", 0);
		assertEquals(10, actual_rela_rodata.size());

		// .text bytes.
		assertSectionBytes(expected_text, 0x00005684, actual_text, 0x00000000, 0x0001bd,
			new Patch(0x00000042,
				new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 }),
			new Patch(0x00000051,
				new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 }),
			new Patch(0x0000007e,
				new byte[] { (byte) 0x7e, (byte) 0xff, (byte) 0xff, (byte) 0xff }),
			new Patch(0x00000088,
				new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 }),
			new Patch(0x000000a2,
				new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 }),
			new Patch(0x000000ae,
				new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 }),
			new Patch(0x000000b8,
				new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 }),
			new Patch(0x000000fd,
				new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 }),
			new Patch(0x00000109,
				new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 }),
			new Patch(0x00000178,
				new byte[] { (byte) 0xe7, (byte) 0xfe, (byte) 0xff, (byte) 0xff }),
			new Patch(0x000001a4,
				new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 }),
			new Patch(0x000001ae,
				new byte[] { (byte) 0xfc, (byte) 0x7f, (byte) 0x0f, (byte) 0x8e }));

		// .rodata bytes.
		assertSectionBytes(expected_rodata, 0x000000bc,
			actual_rodata, 0x00000000, 0xa4);

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
		assertHeader(actualHeader, ELFCLASS64, ELFDATA2LSB, ET_REL, EM_X86_64);

		ElfSectionTable actualSections = actual.getSections();
		var actual_symtab = findSectionByName(actualSections, _SYMTAB, ElfSymbolTable.class);
		var actual_text = findSectionByName(actualSections, _TEXT, ElfProgBits.class);
		var actual_rela_text = findSectionByName(actualSections, _RELA + _TEXT, ElfRelaTable.class);
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
		assertSymbol(actual_symtab, actual_text_index, 0x00000000, "openbsd_isalnum", 47, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x0000002f, "openbsd_isalpha", 47, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x0000005e, "openbsd_iscntrl", 47, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x0000008d, "openbsd_isdigit", 47, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x000000bc, "openbsd_isgraph", 47, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x000000eb, "openbsd_islower", 47, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x0000011a, "openbsd_isprint", 49, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x0000014b, "openbsd_ispunct", 47, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x0000017a, "openbsd_isspace", 47, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x000001a9, "openbsd_isupper", 47, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x000001d8, "openbsd_isxdigit", 47, STT_FUNC,
			STV_DEFAULT, STB_GLOBAL);

		// .rodata symbols.
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000000, 0, STT_SECTION, STV_DEFAULT,
			STB_LOCAL);
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000000, "_openbsd_ctype_", 257,
			STT_OBJECT, STV_DEFAULT, STB_GLOBAL);

		// .rel.text relocations.
		assertRela(actual_rela_text, 0x00000019, R_X86_64_32S, "_openbsd_ctype_", 0);
		assertRela(actual_rela_text, 0x00000048, R_X86_64_32S, "_openbsd_ctype_", 0);
		assertRela(actual_rela_text, 0x00000077, R_X86_64_32S, "_openbsd_ctype_", 0);
		assertRela(actual_rela_text, 0x000000a6, R_X86_64_32S, "_openbsd_ctype_", 0);
		assertRela(actual_rela_text, 0x000000d5, R_X86_64_32S, "_openbsd_ctype_", 0);
		assertRela(actual_rela_text, 0x00000104, R_X86_64_32S, "_openbsd_ctype_", 0);
		assertRela(actual_rela_text, 0x00000133, R_X86_64_32S, "_openbsd_ctype_", 0);
		assertRela(actual_rela_text, 0x00000164, R_X86_64_32S, "_openbsd_ctype_", 0);
		assertRela(actual_rela_text, 0x00000193, R_X86_64_32S, "_openbsd_ctype_", 0);
		assertRela(actual_rela_text, 0x000001c2, R_X86_64_32S, "_openbsd_ctype_", 0);
		assertRela(actual_rela_text, 0x000001f1, R_X86_64_32S, "_openbsd_ctype_", 0);
		assertEquals(11, actual_rela_text.size());

		// .text bytes.
		assertSectionBytes(expected_text, actual_text);

		// .rodata bytes.
		assertSectionBytes(expected_rodata, actual_rodata);
	}
}
