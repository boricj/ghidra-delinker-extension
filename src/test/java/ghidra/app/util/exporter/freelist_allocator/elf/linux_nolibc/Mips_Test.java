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
import static net.boricj.bft.elf.constants.ElfData.ELFDATA2MSB;
import static net.boricj.bft.elf.constants.ElfMachine.EM_MIPS;
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
import net.boricj.bft.elf.sections.ElfNoBits;
import net.boricj.bft.elf.sections.ElfProgBits;
import net.boricj.bft.elf.sections.ElfRelTable;
import net.boricj.bft.elf.sections.ElfSymbolTable;

public class Mips_Test extends DelinkerIntegrationTest {

	private static final File main_file = new File(
		"src/test/resources/programs/freelist-allocator/reference/elf/linux-nolibc/mips/main.o");

	@Override
	protected String getProgramName() {
		return "src/test/resources/programs/freelist-allocator/reference/elf/linux-nolibc/mips/freelist-allocator.elf.gzf";
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
		assertHeader(actualHeader, ELFCLASS32, ELFDATA2MSB, ET_REL, EM_MIPS);

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
		assertSymbol(actual_symtab, actual_text_index, 0x00000000, "allocate_and_fill", 0x90,
			STT_FUNC, STV_DEFAULT, STB_GLOBAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000090, "main", 0x338,
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
		assertSymbol(actual_symtab, actual_rodata_index, 0x000007a8, "s_All_tests_passed._004127d0",
			0x14,
			STT_OBJECT, STV_DEFAULT, STB_LOCAL);

		// .bss symbols
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
		assertRel(actual_rel_text, 0x00000030, R_MIPS_26, "freelist_alloc");
		assertRel(actual_rel_text, 0x0000006c, R_MIPS_26, "memset");
		assertRels(actual_rel_text,
			new Rel(0x000000a0, R_MIPS_HI16, "s_heap"),
			new Rel(0x000000a4, R_MIPS_LO16, "s_heap"));
		assertRel(actual_rel_text, 0x000000b4, R_MIPS_26, "freelist_init");
		assertRels(actual_rel_text,
			new Rel(0x000000bc, R_MIPS_HI16, "s_snapshot_1"),
			new Rel(0x000000c0, R_MIPS_LO16, "s_snapshot_1"),
			new Rel(0x000000c4, R_MIPS_HI16, "s_snapshot_1"),
			new Rel(0x000000c8, R_MIPS_LO16, "s_snapshot_1"),
			new Rel(0x000000cc, R_MIPS_HI16, "s_snapshot_1"),
			new Rel(0x000000d0, R_MIPS_LO16, "s_snapshot_1"));
		assertRel(actual_rel_text, 0x000000e4, R_MIPS_26, "memcmp");
		assertRels(actual_rel_text,
			new Rel(0x0000018c, R_MIPS_HI16, "s_snapshot_2"),
			new Rel(0x00000190, R_MIPS_LO16, "s_snapshot_2"),
			new Rel(0x00000194, R_MIPS_HI16, "s_snapshot_2"),
			new Rel(0x00000198, R_MIPS_LO16, "s_snapshot_2"),
			new Rel(0x0000019c, R_MIPS_HI16, "s_snapshot_2"),
			new Rel(0x000001a0, R_MIPS_LO16, "s_snapshot_2"));
		assertRel(actual_rel_text, 0x000001b4, R_MIPS_26, "memcmp");
		assertRel(actual_rel_text, 0x00000204, R_MIPS_26, "freelist_free");
		assertRels(actual_rel_text,
			new Rel(0x00000228, R_MIPS_HI16, "s_snapshot_3"),
			new Rel(0x0000022c, R_MIPS_LO16, "s_snapshot_3"),
			new Rel(0x00000230, R_MIPS_HI16, "s_snapshot_3"),
			new Rel(0x00000234, R_MIPS_LO16, "s_snapshot_3"),
			new Rel(0x00000238, R_MIPS_HI16, "s_snapshot_3"),
			new Rel(0x0000023c, R_MIPS_LO16, "s_snapshot_3"));
		assertRel(actual_rel_text, 0x00000250, R_MIPS_26, "memcmp");
		assertRel(actual_rel_text, 0x000002a0, R_MIPS_26, "freelist_free");
		assertRels(actual_rel_text,
			new Rel(0x000002c4, R_MIPS_HI16, "s_snapshot_4"),
			new Rel(0x000002c8, R_MIPS_LO16, "s_snapshot_4"),
			new Rel(0x000002cc, R_MIPS_HI16, "s_snapshot_4"),
			new Rel(0x000002d0, R_MIPS_LO16, "s_snapshot_4"),
			new Rel(0x000002d4, R_MIPS_HI16, "s_snapshot_4"),
			new Rel(0x000002d8, R_MIPS_LO16, "s_snapshot_4"));
		assertRel(actual_rel_text, 0x000002ec, R_MIPS_26, "memcmp");
		assertRel(actual_rel_text, 0x00000338, R_MIPS_26, "freelist_free");
		assertRels(actual_rel_text,
			new Rel(0x0000035c, R_MIPS_HI16, "s_snapshot_5"),
			new Rel(0x00000360, R_MIPS_LO16, "s_snapshot_5"),
			new Rel(0x00000364, R_MIPS_HI16, "s_snapshot_5"),
			new Rel(0x00000368, R_MIPS_LO16, "s_snapshot_5"),
			new Rel(0x0000036c, R_MIPS_HI16, "s_snapshot_5"),
			new Rel(0x00000370, R_MIPS_LO16, "s_snapshot_5"));
		assertRel(actual_rel_text, 0x00000384, R_MIPS_26, "memcmp");
		assertRels(actual_rel_text,
			new Rel(0x0000039c, R_MIPS_HI16, "s_All_tests_passed._004127d0"),
			new Rel(0x000003a0, R_MIPS_LO16, "s_All_tests_passed._004127d0"));
		assertRel(actual_rel_text, 0x000003a4, R_MIPS_26, "puts");
		assertEquals(47, actual_rel_text.size());

		// .rodata relocations.
		assertRel(actual_rel_rodata, 0x00000180, R_MIPS_32, "s_heap");
		assertRel(actual_rel_rodata, 0x000001a0, R_MIPS_32, "s_heap");
		assertRel(actual_rel_rodata, 0x000001c0, R_MIPS_32, "s_heap");
		assertRel(actual_rel_rodata, 0x000001e0, R_MIPS_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000200, R_MIPS_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000240, R_MIPS_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000280, R_MIPS_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000300, R_MIPS_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000320, R_MIPS_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000340, R_MIPS_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000360, R_MIPS_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000380, R_MIPS_32, "s_heap");
		assertRel(actual_rel_rodata, 0x000003c0, R_MIPS_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000400, R_MIPS_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000480, R_MIPS_32, "s_heap");
		assertRel(actual_rel_rodata, 0x000004a0, R_MIPS_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000500, R_MIPS_32, "s_heap");
		assertRel(actual_rel_rodata, 0x00000780, R_MIPS_32, "s_snapshot_1");
		assertRel(actual_rel_rodata, 0x00000784, R_MIPS_32, "s_snapshot_1");
		assertRel(actual_rel_rodata, 0x00000788, R_MIPS_32, "s_snapshot_2");
		assertRel(actual_rel_rodata, 0x0000078c, R_MIPS_32, "s_snapshot_2");
		assertRel(actual_rel_rodata, 0x00000790, R_MIPS_32, "s_snapshot_3");
		assertRel(actual_rel_rodata, 0x00000794, R_MIPS_32, "s_snapshot_3");
		assertRel(actual_rel_rodata, 0x00000798, R_MIPS_32, "s_snapshot_4");
		assertRel(actual_rel_rodata, 0x0000079c, R_MIPS_32, "s_snapshot_4");
		assertRel(actual_rel_rodata, 0x000007a0, R_MIPS_32, "s_snapshot_5");
		assertRel(actual_rel_rodata, 0x000007a4, R_MIPS_32, "s_snapshot_5");
		assertEquals(27, actual_rel_rodata.size());

		// .text bytes.
		assertSectionBytes(expected_text, 0x00008824, actual_text, 0x00000000,
			(int) actual_text.getSize(),
			new Patch(0x000000e4, new byte[] { 0x0c, 0x00, 0x00, 0x00 }),
			new Patch(0x00000150, new byte[] { 0x0c, 0x00, 0x00, 0x00 }),
			new Patch(0x000001b4, new byte[] { 0x0c, 0x00, 0x00, 0x00 }),
			new Patch(0x00000250, new byte[] { 0x0c, 0x00, 0x00, 0x00 }),
			new Patch(0x000002ec, new byte[] { 0x0c, 0x00, 0x00, 0x00 }),
			new Patch(0x00000384, new byte[] { 0x0c, 0x00, 0x00, 0x00 }),
			new Patch(0x000003a4, new byte[] { 0x0c, 0x00, 0x00, 0x00 }));

		// .rodata bytes.
		assertSectionBytes(expected_rodata, 0x00000028,
			actual_rodata, 0x00000000, 0x7a8);
		assertSectionBytes(expected_rodata_str1_4, 0x00000074,
			actual_rodata, 0x000007a8, 0x14);
		assertEquals(0x7a8 + 0x14, actual_rodata.getSize());

		// .bss length.
		assertEquals(0x180, actual_bss.getSize());
	}
}