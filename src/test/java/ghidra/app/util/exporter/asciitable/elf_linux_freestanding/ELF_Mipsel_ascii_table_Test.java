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
package ghidra.app.util.exporter.asciitable.elf_linux_freestanding;

import java.io.File;
import java.util.Map;

import org.junit.Test;

import ghidra.DelinkerIntegrationTest;
import ghidra.app.util.bin.format.elf.relocation.MIPS_ElfRelocationType;
import ghidra.app.util.exporter.ElfRelocatableObjectExporter;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;

public class ELF_Mipsel_ascii_table_Test extends DelinkerIntegrationTest {
	private static final File mainFile =
		new File("src/test/resources/ascii-table/reference/elf_linux_freestanding/mipsel/main.o");

	private static final File ctypeFile =
		new File("src/test/resources/ascii-table/reference/elf_linux_freestanding/mipsel/ctype.o");

	@Override
	protected String getProgramName() {
		return "src/test/resources/ascii-table/reference/elf_linux_freestanding/mipsel/ascii-table.elf.gzf";
	}

	@Test
	public void testExport_main_o() throws Exception {
		AddressFactory af = getProgram().getAddressFactory();
		AddressSetView set = af.getAddressSet(af.getAddress("00400150"), af.getAddress("004005ff"))	// .text
				//.union(af.getAddressSet(af.getAddress("00400870"), af.getAddress("004008bb")))      // .text.nolibc_raise
				//.union(af.getAddressSet(af.getAddress("004008bc"), af.getAddress("00400913")))      // .text.nolibc_memove
				//.union(af.getAddressSet(af.getAddress("00400914"), af.getAddress("0040093b")))      // .text.nolibc_memcpy
				//.union(af.getAddressSet(af.getAddress("0040093c"), af.getAddress("0040096b")))      // .text.nolibc_memset
				//.union(af.getAddressSet(af.getAddress("0040096c"), af.getAddress("004009a3")))      // .text.nolibc_abort
				.union(af.getAddressSet(af.getAddress("00410b10"), af.getAddress("00410b17")))      // .sdata
				.union(af.getAddressSet(af.getAddress("004009b0"), af.getAddress("004009ff")))      // .rodata
				.union(af.getAddressSet(af.getAddress("00410b18"), af.getAddress("00410b23")));     // .sbss
		File exportedFile = exportObjectFile(set, new ElfRelocatableObjectExporter(), null);

		Map<Integer, byte[]> text_patches = Map.ofEntries(
			Map.entry(0x140, new byte[2]),
			Map.entry(0x190, new byte[2]),
			Map.entry(0x1f0, new byte[2]),
			Map.entry(0x234, new byte[2]),
			Map.entry(0x27c, new byte[2]),
			Map.entry(0x2e8, new byte[2]),
			Map.entry(0x318, new byte[2]),
			Map.entry(0x32c, new byte[2]),
			Map.entry(0x34c, new byte[2]),
			Map.entry(0x368, new byte[2]),
			Map.entry(0x3ac, new byte[2]),
			Map.entry(0x404, new byte[2]));

		ObjectFile mainObjectFile = new ElfObjectFile(mainFile);
		ElfObjectFile exported = new ElfObjectFile(exportedFile);

		mainObjectFile.compareSectionBytes(".text", exported, ".text", text_patches);
		mainObjectFile.compareSectionSizes(".rel.text", exported, ".rel.text");
		mainObjectFile.compareSectionBytes(".sdata", exported, ".sdata");
		mainObjectFile.compareSectionBytes(".rodata", exported, ".rodata");
		mainObjectFile.compareSectionSizes(".rel.rodata", exported, ".rel.rodata");
		mainObjectFile.compareSectionBytes(".sbss", exported, ".sbss");

		exported.hasSymbolAtAddress(".symtab", "sys_getpid", ".text", 0x00000000);
		exported.hasSymbolAtAddress(".symtab", "sys_kill", ".text", 0x00000024);
		exported.hasSymbolAtAddress(".symtab", "sys_write", ".text", 0x00000048);
		exported.hasSymbolAtAddress(".symtab", "_nolibc_memcpy_up", ".text", 0x0000006c);
		exported.hasSymbolAtAddress(".symtab", "fileno", ".text", 0x000000a4);
		exported.hasSymbolAtAddress(".symtab", "__start", ".text", 0x000000d0);
		exported.hasSymbolAtAddress(".symtab", "write", ".text", 0x00000134);
		exported.hasSymbolAtAddress(".symtab", "fputc", ".text", 0x0000017c);
		exported.hasSymbolAtAddress(".symtab", "putchar", ".text", 0x000001e0);
		exported.hasSymbolAtAddress(".symtab", "print_number", ".text", 0x0000020c);
		exported.hasSymbolAtAddress(".symtab", "print_ascii_entry", ".text", 0x000002a8);
		exported.hasSymbolAtAddress(".symtab", "main", ".text", 0x000003e4);
		exported.hasSymbolAtAddress(".symtab", "s_ascii_properties", ".rodata", 0x00000000);
		exported.hasSymbolAtAddress(".symtab", "COLUMNS", ".sdata", 0x00000000);
		exported.hasSymbolAtAddress(".symtab", "NUM_ASCII_PROPERTIES", ".sdata", 0x00000004);
		exported.hasSymbolAtAddress(".symtab", "errno", ".sbss", 0x00000000);
		exported.hasSymbolAtAddress(".symtab", "_auxv", ".sbss", 0x00000004);
		exported.hasSymbolAtAddress(".symtab", "environ", ".sbss", 0x00000008);

		exported.hasUndefinedSymbol(".symtab", "_gp");
		exported.hasUndefinedSymbol(".symtab", "isalnum");
		exported.hasUndefinedSymbol(".symtab", "isalpha");
		exported.hasUndefinedSymbol(".symtab", "iscntrl");
		exported.hasUndefinedSymbol(".symtab", "isdigit");
		exported.hasUndefinedSymbol(".symtab", "isgraph");
		exported.hasUndefinedSymbol(".symtab", "islower");
		exported.hasUndefinedSymbol(".symtab", "isprint");
		exported.hasUndefinedSymbol(".symtab", "ispunct");
		exported.hasUndefinedSymbol(".symtab", "isspace");
		exported.hasUndefinedSymbol(".symtab", "isupper");

		exported.hasRelocationAtAddress(".rel.text", 0x000000b8,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "errno", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000000c0,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "errno", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000000d0,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "_gp", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000000d4,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "_gp", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000000ec,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "environ", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000000f0,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "environ", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000108,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "_auxv", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x0000010c,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "_auxv", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000120,
			MIPS_ElfRelocationType.R_MIPS_26.typeId(), "main", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x0000013c,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "sys_write", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000140,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "sys_write", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000168,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "errno", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x0000016c,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "errno", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x0000018c,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "fileno", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000190,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "fileno", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000001a8,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "write", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000001ac,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "write", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000001ec,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "fputc", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000001f0,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "fputc", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000230,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "putchar", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000234,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "putchar", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000278,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "putchar", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x0000027c,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "putchar", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000002d0,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "print_number", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000002d4,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "print_number", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000002e4,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "putchar", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000002e8,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "putchar", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000002f8,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "isgraph", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000002fc,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "isgraph", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000314,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "putchar", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000318,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "putchar", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000328,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "putchar", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x0000032c,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "putchar", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000348,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "putchar", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x0000034c,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "putchar", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000364,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "putchar", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000368,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "putchar", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000003a8,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "putchar", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000003ac,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "putchar", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000400,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "putchar", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000404,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "putchar", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000420,
			MIPS_ElfRelocationType.R_MIPS_GPREL16.typeId(), "COLUMNS", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000448,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "s_ascii_properties", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x0000044c,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "s_ascii_properties", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000458,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "print_ascii_entry", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x0000045c,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "print_ascii_entry", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000468,
			MIPS_ElfRelocationType.R_MIPS_GPREL16.typeId(), "COLUMNS", 0);

		exported.hasRelocationAtAddress(".rel.rodata", 0x00000000,
			MIPS_ElfRelocationType.R_MIPS_32.typeId(), "isgraph", 0);
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000008,
			MIPS_ElfRelocationType.R_MIPS_32.typeId(), "isprint", 0);
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000010,
			MIPS_ElfRelocationType.R_MIPS_32.typeId(), "iscntrl", 0);
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000018,
			MIPS_ElfRelocationType.R_MIPS_32.typeId(), "isspace", 0);
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000020,
			MIPS_ElfRelocationType.R_MIPS_32.typeId(), "ispunct", 0);
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000028,
			MIPS_ElfRelocationType.R_MIPS_32.typeId(), "isalnum", 0);
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000030,
			MIPS_ElfRelocationType.R_MIPS_32.typeId(), "isalpha", 0);
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000038,
			MIPS_ElfRelocationType.R_MIPS_32.typeId(), "isdigit", 0);
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000040,
			MIPS_ElfRelocationType.R_MIPS_32.typeId(), "isupper", 0);
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000048,
			MIPS_ElfRelocationType.R_MIPS_32.typeId(), "islower", 0);
	}

	@Test
	public void testExport_ctype_o() throws Exception {
		AddressFactory af = getProgram().getAddressFactory();
		AddressSetView set = af.getAddressSet(af.getAddress("00400600"), af.getAddress("0040086f"))	// .text
				.union(af.getAddressSet(af.getAddress("00400a00"), af.getAddress("00400b0f"))); 	// .rodata
		File exportedFile = exportObjectFile(set, new ElfRelocatableObjectExporter(), null);

		ObjectFile ctypeObjectFile = new ElfObjectFile(ctypeFile);
		ElfObjectFile exported = new ElfObjectFile(exportedFile);

		ctypeObjectFile.compareSectionBytes(".text", exported, ".text");
		ctypeObjectFile.compareSectionSizes(".rel.text", exported, ".rel.text");
		ctypeObjectFile.compareSectionBytes(".rodata", exported, ".rodata");

		exported.hasSymbolAtAddress(".symtab", "isalnum", ".text", 0x00000000);
		exported.hasSymbolAtAddress(".symtab", "isalpha", ".text", 0x00000038);
		exported.hasSymbolAtAddress(".symtab", "iscntrl", ".text", 0x00000070);
		exported.hasSymbolAtAddress(".symtab", "isdigit", ".text", 0x000000a8);
		exported.hasSymbolAtAddress(".symtab", "isgraph", ".text", 0x000000e0);
		exported.hasSymbolAtAddress(".symtab", "islower", ".text", 0x00000118);
		exported.hasSymbolAtAddress(".symtab", "isprint", ".text", 0x00000150);
		exported.hasSymbolAtAddress(".symtab", "ispunct", ".text", 0x00000188);
		exported.hasSymbolAtAddress(".symtab", "isspace", ".text", 0x000001c0);
		exported.hasSymbolAtAddress(".symtab", "isupper", ".text", 0x000001f8);
		exported.hasSymbolAtAddress(".symtab", "isxdigit", ".text", 0x00000230);
		exported.hasSymbolAtAddress(".symtab", "_ctype_", ".rodata", 0x00000000);

		exported.hasRelocationAtAddress(".rel.text", 0x00000010,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000014,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000048,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x0000004c,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000080,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000084,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000000b8,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000000bc,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000000f0,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000000f4,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000128,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x0000012c,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000160,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000164,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000198,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x0000019c,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000001d0,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000001d4,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000208,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x0000020c,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000240,
			MIPS_ElfRelocationType.R_MIPS_HI16.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000244,
			MIPS_ElfRelocationType.R_MIPS_LO16.typeId(), "_ctype_", 0);
	}
}
