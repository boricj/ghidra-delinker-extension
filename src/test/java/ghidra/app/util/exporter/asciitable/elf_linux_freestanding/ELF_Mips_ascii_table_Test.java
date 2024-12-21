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
import ghidra.app.util.exporter.ElfRelocatableObjectExporter;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import net.boricj.bft.elf.machines.mips.ElfRelocationType_Mips;

public class ELF_Mips_ascii_table_Test extends DelinkerIntegrationTest {
	private static final File mainFile =
		new File("src/test/resources/ascii-table/reference/elf_linux_freestanding/mips/main.o");

	private static final File ctypeFile =
		new File("src/test/resources/ascii-table/reference/elf_linux_freestanding/mips/ctype.o");

	@Override
	protected String getProgramName() {
		return "src/test/resources/ascii-table/reference/elf_linux_freestanding/mips/ascii-table.elf.gzf";
	}

	@Test
	public void testExport_main_o() throws Exception {
		AddressFactory af = getProgram().getAddressFactory();
		AddressSetView set = af.getAddressSet(af.getAddress("00400150"), af.getAddress("004005ff"))	// .text
				.union(af.getAddressSet(af.getAddress("00410b10"), af.getAddress("00410b17")))      // .sdata
				.union(af.getAddressSet(af.getAddress("004009b0"), af.getAddress("004009ff")))      // .rodata
				.union(af.getAddressSet(af.getAddress("00410b18"), af.getAddress("00410b23")));     // .sbss
		File exportedFile = exportObjectFile(set, new ElfRelocatableObjectExporter(), null);

		Map<Integer, byte[]> text_patches = Map.ofEntries(
			Map.entry(0x7a, new byte[2]),
			Map.entry(0x12e, new byte[2]),
			Map.entry(0x14a, new byte[2]),
			Map.entry(0x18e, new byte[2]),
			Map.entry(0x236, new byte[2]),
			Map.entry(0x27e, new byte[2]),
			Map.entry(0x2ea, new byte[2]),
			Map.entry(0x31a, new byte[2]),
			Map.entry(0x32e, new byte[2]),
			Map.entry(0x34e, new byte[2]),
			Map.entry(0x36a, new byte[2]),
			Map.entry(0x3ae, new byte[2]),
			Map.entry(0x406, new byte[2]));

		ElfObjectFile mainObjectFile = new ElfObjectFile(mainFile, true);
		ElfObjectFile exported = new ElfObjectFile(exportedFile);

		mainObjectFile.compareSectionBytes(".text", exported, ".text", text_patches);
		mainObjectFile.compareSectionSizes(".rel.text", exported, ".rel.text");
		mainObjectFile.compareSectionBytes(".sdata", exported, ".sdata");
		mainObjectFile.compareSectionBytes(".rodata", exported, ".rodata");
		mainObjectFile.compareSectionSizes(".rel.rodata", exported, ".rel.rodata");
		mainObjectFile.compareSectionSizes(".sbss", exported, ".sbss");

		exported.hasSymbolAtAddress(".symtab", "sys_getpid", ".text", 0x00000000);
		exported.hasSymbolAtAddress(".symtab", "sys_kill", ".text", 0x00000024);
		exported.hasSymbolAtAddress(".symtab", "sys_write", ".text", 0x00000048);
		exported.hasSymbolAtAddress(".symtab", "write", ".text", 0x0000006c);
		exported.hasSymbolAtAddress(".symtab", "_nolibc_memcpy_up", ".text", 0x000000b4);
		exported.hasSymbolAtAddress(".symtab", "fileno", ".text", 0x000000ec);
		exported.hasSymbolAtAddress(".symtab", "fputc", ".text", 0x00000118);
		exported.hasSymbolAtAddress(".symtab", "putchar", ".text", 0x0000017c);
		exported.hasSymbolAtAddress(".symtab", "__start", ".text", 0x000001a8);
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

		exported.hasRelocationAtAddress(".rel.text", 0x00000074,
			ElfRelocationType_Mips.R_MIPS_HI16, "sys_write");
		exported.hasRelocationAtAddress(".rel.text", 0x00000078,
			ElfRelocationType_Mips.R_MIPS_LO16, "sys_write");
		exported.hasRelocationAtAddress(".rel.text", 0x000000a0,
			ElfRelocationType_Mips.R_MIPS_HI16, "errno");
		exported.hasRelocationAtAddress(".rel.text", 0x000000a4,
			ElfRelocationType_Mips.R_MIPS_LO16, "errno");
		exported.hasRelocationAtAddress(".rel.text", 0x00000100,
			ElfRelocationType_Mips.R_MIPS_HI16, "errno");
		exported.hasRelocationAtAddress(".rel.text", 0x00000108,
			ElfRelocationType_Mips.R_MIPS_LO16, "errno");
		exported.hasRelocationAtAddress(".rel.text", 0x00000128,
			ElfRelocationType_Mips.R_MIPS_HI16, "fileno");
		exported.hasRelocationAtAddress(".rel.text", 0x0000012c,
			ElfRelocationType_Mips.R_MIPS_LO16, "fileno");
		exported.hasRelocationAtAddress(".rel.text", 0x00000144,
			ElfRelocationType_Mips.R_MIPS_HI16, "write");
		exported.hasRelocationAtAddress(".rel.text", 0x00000148,
			ElfRelocationType_Mips.R_MIPS_LO16, "write");
		exported.hasRelocationAtAddress(".rel.text", 0x00000188,
			ElfRelocationType_Mips.R_MIPS_HI16, "fputc");
		exported.hasRelocationAtAddress(".rel.text", 0x0000018c,
			ElfRelocationType_Mips.R_MIPS_LO16, "fputc");
		exported.hasRelocationAtAddress(".rel.text", 0x000001bc,
			ElfRelocationType_Mips.R_MIPS_HI16, "environ");
		exported.hasRelocationAtAddress(".rel.text", 0x000001c0,
			ElfRelocationType_Mips.R_MIPS_LO16, "environ");
		exported.hasRelocationAtAddress(".rel.text", 0x000001d8,
			ElfRelocationType_Mips.R_MIPS_HI16, "_auxv");
		exported.hasRelocationAtAddress(".rel.text", 0x000001dc,
			ElfRelocationType_Mips.R_MIPS_LO16, "_auxv");
		exported.hasRelocationAtAddress(".rel.text", 0x000001f0,
			ElfRelocationType_Mips.R_MIPS_HI16, "_gp");
		exported.hasRelocationAtAddress(".rel.text", 0x000001f4,
			ElfRelocationType_Mips.R_MIPS_LO16, "_gp");
		exported.hasRelocationAtAddress(".rel.text", 0x000001f8,
			ElfRelocationType_Mips.R_MIPS_26, "main");
		exported.hasRelocationAtAddress(".rel.text", 0x00000230,
			ElfRelocationType_Mips.R_MIPS_HI16, "putchar");
		exported.hasRelocationAtAddress(".rel.text", 0x00000234,
			ElfRelocationType_Mips.R_MIPS_LO16, "putchar");
		exported.hasRelocationAtAddress(".rel.text", 0x00000278,
			ElfRelocationType_Mips.R_MIPS_HI16, "putchar");
		exported.hasRelocationAtAddress(".rel.text", 0x0000027c,
			ElfRelocationType_Mips.R_MIPS_LO16, "putchar");
		exported.hasRelocationAtAddress(".rel.text", 0x000002d0,
			ElfRelocationType_Mips.R_MIPS_HI16, "print_number");
		exported.hasRelocationAtAddress(".rel.text", 0x000002d4,
			ElfRelocationType_Mips.R_MIPS_LO16, "print_number");
		exported.hasRelocationAtAddress(".rel.text", 0x000002e4,
			ElfRelocationType_Mips.R_MIPS_HI16, "putchar");
		exported.hasRelocationAtAddress(".rel.text", 0x000002e8,
			ElfRelocationType_Mips.R_MIPS_LO16, "putchar");
		exported.hasRelocationAtAddress(".rel.text", 0x000002f8,
			ElfRelocationType_Mips.R_MIPS_HI16, "isgraph");
		exported.hasRelocationAtAddress(".rel.text", 0x000002fc,
			ElfRelocationType_Mips.R_MIPS_LO16, "isgraph");
		exported.hasRelocationAtAddress(".rel.text", 0x00000314,
			ElfRelocationType_Mips.R_MIPS_HI16, "putchar");
		exported.hasRelocationAtAddress(".rel.text", 0x00000318,
			ElfRelocationType_Mips.R_MIPS_LO16, "putchar");
		exported.hasRelocationAtAddress(".rel.text", 0x00000328,
			ElfRelocationType_Mips.R_MIPS_HI16, "putchar");
		exported.hasRelocationAtAddress(".rel.text", 0x0000032c,
			ElfRelocationType_Mips.R_MIPS_LO16, "putchar");
		exported.hasRelocationAtAddress(".rel.text", 0x00000348,
			ElfRelocationType_Mips.R_MIPS_HI16, "putchar");
		exported.hasRelocationAtAddress(".rel.text", 0x0000034c,
			ElfRelocationType_Mips.R_MIPS_LO16, "putchar");
		exported.hasRelocationAtAddress(".rel.text", 0x00000364,
			ElfRelocationType_Mips.R_MIPS_HI16, "putchar");
		exported.hasRelocationAtAddress(".rel.text", 0x00000368,
			ElfRelocationType_Mips.R_MIPS_LO16, "putchar");
		exported.hasRelocationAtAddress(".rel.text", 0x000003a8,
			ElfRelocationType_Mips.R_MIPS_HI16, "putchar");
		exported.hasRelocationAtAddress(".rel.text", 0x000003ac,
			ElfRelocationType_Mips.R_MIPS_LO16, "putchar");
		exported.hasRelocationAtAddress(".rel.text", 0x00000400,
			ElfRelocationType_Mips.R_MIPS_HI16, "putchar");
		exported.hasRelocationAtAddress(".rel.text", 0x00000404,
			ElfRelocationType_Mips.R_MIPS_LO16, "putchar");
		exported.hasRelocationAtAddress(".rel.text", 0x00000420,
			ElfRelocationType_Mips.R_MIPS_GPREL16, "COLUMNS");
		exported.hasRelocationAtAddress(".rel.text", 0x00000448,
			ElfRelocationType_Mips.R_MIPS_HI16, "s_ascii_properties");
		exported.hasRelocationAtAddress(".rel.text", 0x0000044c,
			ElfRelocationType_Mips.R_MIPS_LO16, "s_ascii_properties");
		exported.hasRelocationAtAddress(".rel.text", 0x00000458,
			ElfRelocationType_Mips.R_MIPS_HI16, "print_ascii_entry");
		exported.hasRelocationAtAddress(".rel.text", 0x0000045c,
			ElfRelocationType_Mips.R_MIPS_LO16, "print_ascii_entry");
		exported.hasRelocationAtAddress(".rel.text", 0x00000468,
			ElfRelocationType_Mips.R_MIPS_GPREL16, "COLUMNS");

		exported.hasRelocationAtAddress(".rel.rodata", 0x00000000,
			ElfRelocationType_Mips.R_MIPS_32, "isgraph");
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000008,
			ElfRelocationType_Mips.R_MIPS_32, "isprint");
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000010,
			ElfRelocationType_Mips.R_MIPS_32, "iscntrl");
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000018,
			ElfRelocationType_Mips.R_MIPS_32, "isspace");
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000020,
			ElfRelocationType_Mips.R_MIPS_32, "ispunct");
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000028,
			ElfRelocationType_Mips.R_MIPS_32, "isalnum");
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000030,
			ElfRelocationType_Mips.R_MIPS_32, "isalpha");
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000038,
			ElfRelocationType_Mips.R_MIPS_32, "isdigit");
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000040,
			ElfRelocationType_Mips.R_MIPS_32, "isupper");
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000048,
			ElfRelocationType_Mips.R_MIPS_32, "islower");
	}

	@Test
	public void testExport_ctype_o() throws Exception {
		AddressFactory af = getProgram().getAddressFactory();
		AddressSetView set = af.getAddressSet(af.getAddress("00400600"), af.getAddress("0040086f"))	// .text
				.union(af.getAddressSet(af.getAddress("00400a00"), af.getAddress("00400b0f"))); 	// .rodata
		File exportedFile = exportObjectFile(set, new ElfRelocatableObjectExporter(), null);

		ElfObjectFile ctypeObjectFile = new ElfObjectFile(ctypeFile, true);
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
			ElfRelocationType_Mips.R_MIPS_HI16, "_ctype_");
		exported.hasRelocationAtAddress(".rel.text", 0x00000014,
			ElfRelocationType_Mips.R_MIPS_LO16, "_ctype_");
		exported.hasRelocationAtAddress(".rel.text", 0x00000048,
			ElfRelocationType_Mips.R_MIPS_HI16, "_ctype_");
		exported.hasRelocationAtAddress(".rel.text", 0x0000004c,
			ElfRelocationType_Mips.R_MIPS_LO16, "_ctype_");
		exported.hasRelocationAtAddress(".rel.text", 0x00000080,
			ElfRelocationType_Mips.R_MIPS_HI16, "_ctype_");
		exported.hasRelocationAtAddress(".rel.text", 0x00000084,
			ElfRelocationType_Mips.R_MIPS_LO16, "_ctype_");
		exported.hasRelocationAtAddress(".rel.text", 0x000000b8,
			ElfRelocationType_Mips.R_MIPS_HI16, "_ctype_");
		exported.hasRelocationAtAddress(".rel.text", 0x000000bc,
			ElfRelocationType_Mips.R_MIPS_LO16, "_ctype_");
		exported.hasRelocationAtAddress(".rel.text", 0x000000f0,
			ElfRelocationType_Mips.R_MIPS_HI16, "_ctype_");
		exported.hasRelocationAtAddress(".rel.text", 0x000000f4,
			ElfRelocationType_Mips.R_MIPS_LO16, "_ctype_");
		exported.hasRelocationAtAddress(".rel.text", 0x00000128,
			ElfRelocationType_Mips.R_MIPS_HI16, "_ctype_");
		exported.hasRelocationAtAddress(".rel.text", 0x0000012c,
			ElfRelocationType_Mips.R_MIPS_LO16, "_ctype_");
		exported.hasRelocationAtAddress(".rel.text", 0x00000160,
			ElfRelocationType_Mips.R_MIPS_HI16, "_ctype_");
		exported.hasRelocationAtAddress(".rel.text", 0x00000164,
			ElfRelocationType_Mips.R_MIPS_LO16, "_ctype_");
		exported.hasRelocationAtAddress(".rel.text", 0x00000198,
			ElfRelocationType_Mips.R_MIPS_HI16, "_ctype_");
		exported.hasRelocationAtAddress(".rel.text", 0x0000019c,
			ElfRelocationType_Mips.R_MIPS_LO16, "_ctype_");
		exported.hasRelocationAtAddress(".rel.text", 0x000001d0,
			ElfRelocationType_Mips.R_MIPS_HI16, "_ctype_");
		exported.hasRelocationAtAddress(".rel.text", 0x000001d4,
			ElfRelocationType_Mips.R_MIPS_LO16, "_ctype_");
		exported.hasRelocationAtAddress(".rel.text", 0x00000208,
			ElfRelocationType_Mips.R_MIPS_HI16, "_ctype_");
		exported.hasRelocationAtAddress(".rel.text", 0x0000020c,
			ElfRelocationType_Mips.R_MIPS_LO16, "_ctype_");
		exported.hasRelocationAtAddress(".rel.text", 0x00000240,
			ElfRelocationType_Mips.R_MIPS_HI16, "_ctype_");
		exported.hasRelocationAtAddress(".rel.text", 0x00000244,
			ElfRelocationType_Mips.R_MIPS_LO16, "_ctype_");
	}
}
