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
package ghidra.app.util.exporter.freelistallocator.elf_linux_nolibc;

import static net.boricj.bft.elf.constants.ElfClass.ELFCLASS64;
import static net.boricj.bft.elf.constants.ElfData.ELFDATA2LSB;
import static net.boricj.bft.elf.constants.ElfMachine.EM_X86_64;
import static net.boricj.bft.elf.constants.ElfType.ET_REL;
import static net.boricj.bft.elf.ElfSection.SHN_UNDEF;
import static net.boricj.bft.elf.constants.ElfSectionNames._BSS;
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
import net.boricj.bft.elf.sections.ElfNoBits;
import net.boricj.bft.elf.sections.ElfProgBits;
import net.boricj.bft.elf.sections.ElfRelaTable;
import net.boricj.bft.elf.sections.ElfSymbolTable;

public class X86_64_Test extends DelinkerIntegrationTest {

	private static final File main_file = new File(
		"src/test/resources/programs/freelist-allocator/reference/elf/linux-nolibc/x86_64/main.o");

	@Override
	protected String getProgramName() {
		return "src/test/resources/programs/freelist-allocator/reference/elf/linux-nolibc/x86_64/freelist-allocator.elf.gzf";
	}

	@Test
	public void test_main_o() throws Exception {
		// Expected file.
		ElfFile expected = new ElfFile.Parser(new FileInputStream(main_file)).parse();

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
		var actual_bss = findSectionByName(actualSections, _BSS, ElfNoBits.class);
		var actual_rela_rodata =
			findSectionByName(actualSections, _RELA + _RODATA, ElfRelaTable.class);

		int actual_text_index = sectionNumber(actualSections, actual_text);
		int actual_rodata_index = sectionNumber(actualSections, actual_rodata);
		int actual_bss_index = sectionNumber(actualSections, actual_bss);

		// .text section flags.
		assertTrue(actual_text.getFlags().isAlloc());
		assertFalse(actual_text.getFlags().isWrite());
		assertTrue(actual_text.getFlags().isExecInstr());

		// .rodata section flags.
		assertTrue(actual_rodata.getFlags().isAlloc());
		assertFalse(actual_rodata.getFlags().isWrite());
		assertFalse(actual_rodata.getFlags().isExecInstr());

		// .bss section flags.
		assertTrue(actual_bss.getFlags().isAlloc());
		assertTrue(actual_bss.getFlags().isWrite());
		assertFalse(actual_bss.getFlags().isExecInstr());

		// .text symbols.
		assertSymbol(actual_symtab, actual_text_index, 0x00000000, 0,
			STT_SECTION, STV_DEFAULT, STB_LOCAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000000, "allocate_and_fill", 0x5e,
			STT_FUNC, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x0000005e, "main", 0x203,
			STT_FUNC, STV_DEFAULT, STB_GLOBAL);

		// .rodata symbols.
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000000, 0,
			STT_SECTION, STV_DEFAULT, STB_LOCAL);
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000000, "s_snapshot_1", 0x180,
			STT_OBJECT, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000180, "s_snapshot_2", 0x180,
			STT_OBJECT, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000300, "s_snapshot_3", 0x180,
			STT_OBJECT, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000480, "s_snapshot_4", 0x180,
			STT_OBJECT, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000600, "s_snapshot_5", 0x180,
			STT_OBJECT, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000780, "s_heap_ranges", 0x50,
			STT_OBJECT, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_rodata_index, 0x000007d0, "s_All_tests_passed._0040d890",
			18, STT_OBJECT, STV_DEFAULT, STB_LOCAL);
		assertSymbol(actual_symtab, actual_bss_index, 0x00000000, 0,
			STT_SECTION, STV_DEFAULT, STB_LOCAL);
		assertSymbol(actual_symtab, actual_bss_index, 0x00000000, "s_heap", 0x180,
			STT_OBJECT, STV_DEFAULT, STB_GLOBAL);

		// Undefined symbols.
		assertSymbol(actual_symtab, SHN_UNDEF, 0x00000000, "freelist_alloc", 0,
			STT_NOTYPE, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, SHN_UNDEF, 0x00000000, "freelist_init", 0,
			STT_NOTYPE, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, SHN_UNDEF, 0x00000000, "freelist_free", 0,
			STT_NOTYPE, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, SHN_UNDEF, 0x00000000, "memcmp", 0,
			STT_NOTYPE, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, SHN_UNDEF, 0x00000000, "memset", 0,
			STT_NOTYPE, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, SHN_UNDEF, 0x00000000, "puts", 0,
			STT_NOTYPE, STV_DEFAULT, STB_GLOBAL);

		// .text relocations.
		assertRela(actual_rela_text, 0x00000028, R_X86_64_PC32, "freelist_alloc", -4);
		assertRela(actual_rela_text, 0x00000054, R_X86_64_PC32, "memset", -4);
		assertRela(actual_rela_text, 0x0000006a, R_X86_64_32S, "s_heap", 0);
		assertRela(actual_rela_text, 0x0000007b, R_X86_64_PC32, "freelist_init", -4);
		assertRela(actual_rela_text, 0x00000080, R_X86_64_32S, "s_snapshot_2", 0);
		assertRela(actual_rela_text, 0x00000085, R_X86_64_32S, "s_snapshot_1", 0);
		assertRela(actual_rela_text, 0x00000090, R_X86_64_32S, "s_snapshot_1", 0);
		assertRela(actual_rela_text, 0x0000009f, R_X86_64_PC32, "memcmp", -4);
		assertRela(actual_rela_text, 0x00000100, R_X86_64_32S, "s_snapshot_3", 0);
		assertRela(actual_rela_text, 0x00000105, R_X86_64_32S, "s_snapshot_2", 0);
		assertRela(actual_rela_text, 0x00000110, R_X86_64_32S, "s_snapshot_2", 0);
		assertRela(actual_rela_text, 0x0000011f, R_X86_64_PC32, "memcmp", -4);
		assertRela(actual_rela_text, 0x00000152, R_X86_64_PC32, "freelist_free", -4);
		assertRela(actual_rela_text, 0x00000163, R_X86_64_32S, "s_snapshot_4", 0);
		assertRela(actual_rela_text, 0x00000168, R_X86_64_32S, "s_snapshot_3", 0);
		assertRela(actual_rela_text, 0x00000173, R_X86_64_32S, "s_snapshot_3", 0);
		assertRela(actual_rela_text, 0x00000182, R_X86_64_PC32, "memcmp", -4);
		assertRela(actual_rela_text, 0x000001b5, R_X86_64_PC32, "freelist_free", -4);
		assertRela(actual_rela_text, 0x000001c6, R_X86_64_32S, "s_snapshot_5", 0);
		assertRela(actual_rela_text, 0x000001cb, R_X86_64_32S, "s_snapshot_4", 0);
		assertRela(actual_rela_text, 0x000001d6, R_X86_64_32S, "s_snapshot_4", 0);
		assertRela(actual_rela_text, 0x000001e5, R_X86_64_PC32, "memcmp", -4);
		assertRela(actual_rela_text, 0x00000215, R_X86_64_PC32, "freelist_free", -4);
		assertRela(actual_rela_text, 0x00000226, R_X86_64_32S, "s_heap_ranges", 0);
		assertRela(actual_rela_text, 0x0000022b, R_X86_64_32S, "s_snapshot_5", 0);
		assertRela(actual_rela_text, 0x00000236, R_X86_64_32S, "s_snapshot_5", 0);
		assertRela(actual_rela_text, 0x00000245, R_X86_64_PC32, "memcmp", -4);
		assertRela(actual_rela_text, 0x00000253, R_X86_64_32S, "s_All_tests_passed._0040d890", 0);
		assertRela(actual_rela_text, 0x00000258, R_X86_64_PC32, "puts", -4);
		assertEquals(29, actual_rela_text.size());

		// .rodata relocations.
		assertRela(actual_rela_rodata, 0x00000180, R_X86_64_64, "s_heap", 0x20);
		assertRela(actual_rela_rodata, 0x000001a0, R_X86_64_64, "s_heap", 0x40);
		assertRela(actual_rela_rodata, 0x000001c0, R_X86_64_64, "s_heap", 0x60);
		assertRela(actual_rela_rodata, 0x000001e0, R_X86_64_64, "s_heap", 0x80);
		assertRela(actual_rela_rodata, 0x00000200, R_X86_64_64, "s_heap", 0xc0);
		assertRela(actual_rela_rodata, 0x00000240, R_X86_64_64, "s_heap", 0x100);
		assertRela(actual_rela_rodata, 0x00000280, R_X86_64_64, "s_heap", 0x140);
		assertRela(actual_rela_rodata, 0x00000300, R_X86_64_64, "s_heap", 0x20);
		assertRela(actual_rela_rodata, 0x00000320, R_X86_64_64, "s_heap", 0x40);
		assertRela(actual_rela_rodata, 0x00000340, R_X86_64_64, "s_heap", 0x60);
		assertRela(actual_rela_rodata, 0x00000360, R_X86_64_64, "s_heap", 0x80);
		assertRela(actual_rela_rodata, 0x00000380, R_X86_64_64, "s_heap", 0xc0);
		assertRela(actual_rela_rodata, 0x000003c0, R_X86_64_64, "s_heap", 0x100);
		assertRela(actual_rela_rodata, 0x00000400, R_X86_64_64, "s_heap", 0x140);
		assertRela(actual_rela_rodata, 0x00000480, R_X86_64_64, "s_heap", 0x20);
		assertRela(actual_rela_rodata, 0x000004a0, R_X86_64_64, "s_heap", 0x80);
		assertRela(actual_rela_rodata, 0x00000500, R_X86_64_64, "s_heap", 0xc0);
		assertRela(actual_rela_rodata, 0x00000780, R_X86_64_64, "s_snapshot_1", 0);
		assertRela(actual_rela_rodata, 0x00000788, R_X86_64_64, "s_snapshot_1", 0x180);
		assertRela(actual_rela_rodata, 0x00000790, R_X86_64_64, "s_snapshot_2", 0);
		assertRela(actual_rela_rodata, 0x00000798, R_X86_64_64, "s_snapshot_2", 0x180);
		assertRela(actual_rela_rodata, 0x000007a0, R_X86_64_64, "s_snapshot_3", 0);
		assertRela(actual_rela_rodata, 0x000007a8, R_X86_64_64, "s_snapshot_3", 0x180);
		assertRela(actual_rela_rodata, 0x000007b0, R_X86_64_64, "s_snapshot_4", 0);
		assertRela(actual_rela_rodata, 0x000007b8, R_X86_64_64, "s_snapshot_4", 0x180);
		assertRela(actual_rela_rodata, 0x000007c0, R_X86_64_64, "s_snapshot_5", 0);
		assertRela(actual_rela_rodata, 0x000007c8, R_X86_64_64, "s_snapshot_5", 0x180);
		assertEquals(27, actual_rela_rodata.size());

		// .text bytes.
		assertSectionBytes(expected_text, 0x00005684,
			actual_text, 0x00000000, (int) actual_text.getSize(),
			new Patch(0x0000009f, new byte[] { 0x00, 0x00, 0x00, 0x00 }),
			new Patch(0x0000011f, new byte[] { 0x00, 0x00, 0x00, 0x00 }),
			new Patch(0x00000182, new byte[] { 0x00, 0x00, 0x00, 0x00 }),
			new Patch(0x000001e5, new byte[] { 0x00, 0x00, 0x00, 0x00 }),
			new Patch(0x00000245, new byte[] { 0x00, 0x00, 0x00, 0x00 }),
			new Patch(0x00000258, new byte[] { 0x00, 0x00, 0x00, 0x00 }));

		// .rodata bytes.
		assertSectionBytes(expected_rodata, 0x000000c0,
			actual_rodata, 0x00000000, (int) actual_rodata.getSize());

		// .bss length.
		assertEquals(0x180, actual_bss.getSize());
	}
}
