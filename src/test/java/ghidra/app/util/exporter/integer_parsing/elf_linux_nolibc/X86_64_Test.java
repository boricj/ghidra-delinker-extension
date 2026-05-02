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
import static net.boricj.bft.elf.constants.ElfClass.ELFCLASS64;
import static net.boricj.bft.elf.constants.ElfData.ELFDATA2LSB;
import static net.boricj.bft.elf.constants.ElfMachine.EM_X86_64;
import static net.boricj.bft.elf.constants.ElfSectionNames._RELA;
import static net.boricj.bft.elf.constants.ElfSectionNames._RODATA;
import static net.boricj.bft.elf.constants.ElfSectionNames._SYMTAB;
import static net.boricj.bft.elf.constants.ElfSectionNames._TEXT;
import static net.boricj.bft.elf.constants.ElfSymbolBinding.STB_GLOBAL;
import static net.boricj.bft.elf.constants.ElfSymbolType.STT_FUNC;
import static net.boricj.bft.elf.constants.ElfSymbolType.STT_NOTYPE;
import static net.boricj.bft.elf.constants.ElfSymbolType.STT_OBJECT;
import static net.boricj.bft.elf.constants.ElfSymbolVisibility.STV_DEFAULT;
import static net.boricj.bft.elf.constants.ElfType.ET_REL;
import static net.boricj.bft.elf.machines.amd64.ElfRelocationType_amd64.R_X86_64_32S;
import static net.boricj.bft.elf.machines.amd64.ElfRelocationType_amd64.R_X86_64_64;
import static net.boricj.bft.elf.machines.amd64.ElfRelocationType_amd64.R_X86_64_PC32;

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
import net.boricj.bft.elf.sections.ElfRelaTable;
import net.boricj.bft.elf.sections.ElfSymbolTable;

public class X86_64_Test extends DelinkerIntegrationTest {

	private static final File main_file = new File(
		"src/test/resources/programs/integer-parsing/reference/elf/linux-nolibc/x86_64/main.o");

	@Override
	protected String getProgramName() {
		return "src/test/resources/programs/integer-parsing/reference/elf/linux-nolibc/x86_64/integer-parsing.elf.gzf";
	}

	@Test
	public void test_main_o() throws Exception {
		// Expected file.
		ElfFile expected =
			new ElfFile.Parser(new FileInputStream(main_file)).setIgnoreSectionErrors(true).parse();

		ElfSectionTable expectedSections = expected.getSections();
		var expected_text = findSectionByName(expectedSections, _TEXT, ElfProgBits.class);
		var expected_rodata = findSectionByName(expectedSections, _RODATA, ElfProgBits.class);

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

		// .text section flags.
		assertTrue(actual_text.getFlags().isAlloc());
		assertFalse(actual_text.getFlags().isWrite());
		assertTrue(actual_text.getFlags().isExecInstr());

		// .rodata section flags.
		assertTrue(actual_rodata.getFlags().isAlloc());
		assertFalse(actual_rodata.getFlags().isWrite());
		assertFalse(actual_rodata.getFlags().isExecInstr());

		// Key symbols.
		assertSymbol(actual_symtab, 1, 0x00000000, "parse_decimal", 0x51,
			STT_FUNC, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, 1, 0x00000051, "main", 0x58,
			STT_FUNC, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, 2, 0x00000002, "s_ascii_digit_bias", 0x8,
			STT_OBJECT, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, SHN_UNDEF, 0x00000000, "puts", 0,
			STT_NOTYPE, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, SHN_UNDEF, 0x00000000, "s_digits", 0,
			STT_NOTYPE, STV_DEFAULT, STB_GLOBAL);

		// .text relocations.
		assertRela(actual_rela_text, 0x00000020, R_X86_64_32S, "s_digits", -0xc0);
		assertRela(actual_rela_text, 0x00000056, R_X86_64_32S, "s_0_00407046", 0);
		assertRela(actual_rela_text, 0x0000006b, R_X86_64_32S, "s_123_004070c8", 0);
		assertRela(actual_rela_text, 0x00000081, R_X86_64_32S, "s_65535_004070cc", 0);
		assertRela(actual_rela_text, 0x00000099, R_X86_64_32S, "s_All_tests_passed._004070d2", 0);
		assertRela(actual_rela_text, 0x0000009e, R_X86_64_PC32, "puts", -4);
		assertEquals(6, actual_rela_text.size());

		// .rodata relocations.
		assertRela(actual_rela_rodata, 0x00000002, R_X86_64_64, "s_digits", -0xc0);
		assertEquals(1, actual_rela_rodata.size());

		// .text bytes.
		assertSectionBytes(expected_text, 0x5684, actual_text, 0, actual_text.getBytes().length,
			new Patch(0x0000005b,
				new byte[] { (byte) 0xa1, (byte) 0xff, (byte) 0xff, (byte) 0xff }),
			new Patch(0x00000070,
				new byte[] { (byte) 0x8c, (byte) 0xff, (byte) 0xff, (byte) 0xff }),
			new Patch(0x00000086, new byte[] { 0x76, (byte) 0xff, (byte) 0xff, (byte) 0xff }),
			new Patch(0x0000009e, new byte[] { 0x00, 0x00, 0x00, 0x00 }));

		// .rodata bytes.
		assertSectionBytes(expected_rodata, 0x00000046,
			actual_rodata, 0x00000000, 0x2);
		assertSectionBytes(expected_rodata, 0x000000c8,
			actual_rodata, 0x0000000a, (int) actual_rodata.getSize() - 0x0a);
	}
}
