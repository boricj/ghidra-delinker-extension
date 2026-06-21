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
package ghidra.app.util.exporter.freelist_allocator.elf.linux_nolibc;

import static net.boricj.bft.elf.ElfSection.SHN_UNDEF;
import static net.boricj.bft.elf.constants.ElfClass.ELFCLASS32;
import static net.boricj.bft.elf.constants.ElfData.ELFDATA2LSB;
import static net.boricj.bft.elf.constants.ElfMachine.EM_386;
import static net.boricj.bft.elf.constants.ElfSectionNames._BSS;
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
import static net.boricj.bft.elf.machines.i386.ElfRelocationType_i386.R_386_32;
import static net.boricj.bft.elf.machines.i386.ElfRelocationType_i386.R_386_PC32;
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
import net.boricj.bft.elf.sections.ElfRelTable;
import net.boricj.bft.elf.sections.ElfSymbolTable;

public class I686_Test extends DelinkerIntegrationTest {

	private static final File main_file = new File(
		"src/test/resources/programs/freelist-allocator/reference/elf/linux-nolibc/i686/main.o");

	@Override
	protected String getProgramName() {
		return "src/test/resources/programs/freelist-allocator/reference/elf/linux-nolibc/i686/freelist-allocator.elf.gzf";
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
		assertHeader(actualHeader, ELFCLASS32, ELFDATA2LSB, ET_REL, EM_386);

		ElfSectionTable actualSections = actual.getSections();
		var actual_symtab = findSectionByName(actualSections, _SYMTAB, ElfSymbolTable.class);
		var actual_text = findSectionByName(actualSections, _TEXT, ElfProgBits.class);
		var actual_rel_text = findSectionByName(actualSections, _REL + _TEXT, ElfRelTable.class);
		var actual_rodata = findSectionByName(actualSections, _RODATA, ElfProgBits.class);
		var actual_bss = findSectionByName(actualSections, _BSS, ElfNoBits.class);
		var actual_rel_rodata =
			findSectionByName(actualSections, _REL + _RODATA, ElfRelTable.class);

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
		assertSymbol(actual_symtab, actual_text_index, 0x00000000, "allocate_and_fill", 0x50,
			STT_FUNC, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000050, "main", 0x1ff,
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
		assertSymbol(actual_symtab, actual_rodata_index, 0x00000780, "s_heap_ranges", 0x28,
			STT_OBJECT, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_rodata_index, 0x000007a8, "s_All_tests_passed._08052848",
			0x12,
			STT_OBJECT, STV_DEFAULT, STB_LOCAL);

		// .bss symbols.
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
		assertRel(actual_rel_text, 0x0000001a, R_386_PC32, "freelist_alloc");
		assertRel(actual_rel_text, 0x00000044, R_386_PC32, "memset");
		assertRel(actual_rel_text, 0x00000064, R_386_32, "s_heap");
		assertRel(actual_rel_text, 0x00000074, R_386_PC32, "freelist_init");
		assertRel(actual_rel_text, 0x0000007c, R_386_32, "s_snapshot_2");
		assertRel(actual_rel_text, 0x00000081, R_386_32, "s_snapshot_1");
		assertRel(actual_rel_text, 0x0000008a, R_386_32, "s_snapshot_1");
		assertRel(actual_rel_text, 0x000000f5, R_386_32, "s_snapshot_3");
		assertRel(actual_rel_text, 0x000000fa, R_386_32, "s_snapshot_2");
		assertRel(actual_rel_text, 0x00000103, R_386_32, "s_snapshot_2");
		assertRel(actual_rel_text, 0x00000140, R_386_PC32, "freelist_free");
		assertRel(actual_rel_text, 0x00000152, R_386_32, "s_snapshot_4");
		assertRel(actual_rel_text, 0x00000157, R_386_32, "s_snapshot_3");
		assertRel(actual_rel_text, 0x00000160, R_386_32, "s_snapshot_3");
		assertRel(actual_rel_text, 0x0000019d, R_386_PC32, "freelist_free");
		assertRel(actual_rel_text, 0x000001af, R_386_32, "s_snapshot_5");
		assertRel(actual_rel_text, 0x000001b4, R_386_32, "s_snapshot_4");
		assertRel(actual_rel_text, 0x000001bd, R_386_32, "s_snapshot_4");
		assertRel(actual_rel_text, 0x000001f7, R_386_PC32, "freelist_free");
		assertRel(actual_rel_text, 0x00000209, R_386_32, "s_heap_ranges");
		assertRel(actual_rel_text, 0x0000020e, R_386_32, "s_snapshot_5");
		assertRel(actual_rel_text, 0x00000217, R_386_32, "s_snapshot_5");
		assertRel(actual_rel_text, 0x00000097, R_386_PC32, "memcmp");
		assertRel(actual_rel_text, 0x00000110, R_386_PC32, "memcmp");
		assertRel(actual_rel_text, 0x0000016d, R_386_PC32, "memcmp");
		assertRel(actual_rel_text, 0x000001ca, R_386_PC32, "memcmp");
		assertRel(actual_rel_text, 0x00000224, R_386_PC32, "memcmp");
		assertRel(actual_rel_text, 0x00000238, R_386_32, "s_All_tests_passed._08052848");
		assertRel(actual_rel_text, 0x0000023d, R_386_PC32, "puts");
		assertEquals(29, actual_rel_text.size());

		// .rodata relocations.
		assertRel(actual_rel_rodata, 0x00000180, R_386_32, "s_heap");
		assertRel(actual_rel_rodata, 0x000001a0, R_386_32, "s_heap");
		assertRel(actual_rel_rodata, 0x000001c0, R_386_32, "s_heap");
		assertRel(actual_rel_rodata, 0x000001e0, R_386_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000200, R_386_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000240, R_386_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000280, R_386_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000300, R_386_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000320, R_386_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000340, R_386_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000360, R_386_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000380, R_386_32, "s_heap");
		assertRel(actual_rel_rodata, 0x000003c0, R_386_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000400, R_386_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000480, R_386_32, "s_heap");
		assertRel(actual_rel_rodata, 0x000004a0, R_386_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000500, R_386_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000780, R_386_32, "s_snapshot_1");
		assertRel(actual_rel_rodata, 0x00000784, R_386_32, "s_snapshot_1");
		assertRel(actual_rel_rodata, 0x00000788, R_386_32, "s_snapshot_2");
		assertRel(actual_rel_rodata, 0x0000078c, R_386_32, "s_snapshot_2");
		assertRel(actual_rel_rodata, 0x00000790, R_386_32, "s_snapshot_3");
		assertRel(actual_rel_rodata, 0x00000794, R_386_32, "s_snapshot_3");
		assertRel(actual_rel_rodata, 0x00000798, R_386_32, "s_snapshot_4");
		assertRel(actual_rel_rodata, 0x0000079c, R_386_32, "s_snapshot_4");
		assertRel(actual_rel_rodata, 0x000007a0, R_386_32, "s_snapshot_5");
		assertRel(actual_rel_rodata, 0x000007a4, R_386_32, "s_snapshot_5");
		assertEquals(27, actual_rel_rodata.size());

		// .text bytes.
		assertSectionBytes(expected_text, 0x00004078, actual_text, 0x00000000,
			(int) actual_text.getSize(),
			new Patch(0x0000007c, new byte[] { 0x00, 0x00, 0x00, 0x00 }),
			new Patch(0x00000097, new byte[] { (byte) 0xfc, (byte) 0xff, (byte) 0xff,
				(byte) 0xff }),
			new Patch(0x000000f5, new byte[] { 0x00, 0x00, 0x00, 0x00 }),
			new Patch(0x00000110, new byte[] { (byte) 0xfc, (byte) 0xff, (byte) 0xff,
				(byte) 0xff }),
			new Patch(0x00000152, new byte[] { 0x00, 0x00, 0x00, 0x00 }),
			new Patch(0x0000016d, new byte[] { (byte) 0xfc, (byte) 0xff, (byte) 0xff,
				(byte) 0xff }),
			new Patch(0x000001af, new byte[] { 0x00, 0x00, 0x00, 0x00 }),
			new Patch(0x000001ca, new byte[] { (byte) 0xfc, (byte) 0xff, (byte) 0xff,
				(byte) 0xff }),
			new Patch(0x00000209, new byte[] { 0x00, 0x00, 0x00, 0x00 }),
			new Patch(0x00000224, new byte[] { (byte) 0xfc, (byte) 0xff, (byte) 0xff,
				(byte) 0xff }),
			new Patch(0x00000238, new byte[] { 0x00, 0x00, 0x00, 0x00 }),
			new Patch(0x0000023d, new byte[] { (byte) 0xfc, (byte) 0xff, (byte) 0xff,
				(byte) 0xff }));

		// .rodata bytes.
		assertSectionBytes(expected_rodata, 0x000000a0,
			actual_rodata, 0x00000000, (int) actual_rodata.getSize());

		// .bss length.
		assertEquals(0x180, actual_bss.getSize());
	}
}
