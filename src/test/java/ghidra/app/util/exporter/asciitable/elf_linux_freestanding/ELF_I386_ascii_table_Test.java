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
import ghidra.app.util.bin.format.elf.relocation.X86_32_ElfRelocationType;
import ghidra.app.util.exporter.ElfRelocatableObjectExporter;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;

public class ELF_I386_ascii_table_Test extends DelinkerIntegrationTest {
	private static final File mainFile =
		new File("src/test/resources/ascii-table/reference/elf_linux_freestanding/i386/main.o");

	private static final File ctypeFile =
		new File("src/test/resources/ascii-table/reference/elf_linux_freestanding/i386/ctype.o");

	@Override
	protected String getProgramName() {
		return "src/test/resources/ascii-table/reference/elf_linux_freestanding/i386/ascii-table.elf.gzf";
	}

	@Test
	public void testExport_main_o() throws Exception {
		AddressFactory af = getProgram().getAddressFactory();
		AddressSetView set = af.getAddressSet(af.getAddress("08049000"), af.getAddress("0804924d"))	// .text
				.union(af.getAddressSet(af.getAddress("0804b000"), af.getAddress("0804b003")))	 	// .data
				.union(af.getAddressSet(af.getAddress("0804a000"), af.getAddress("0804a053"))); 	// .rodata
		File exportedFile = exportObjectFile(set, new ElfRelocatableObjectExporter(), null);

		Map<Integer, byte[]> text_patches = Map.ofEntries(
			Map.entry(0x8a, new byte[] { 0x3e, 0x01, 0x00, 0x00 }),
			Map.entry(0xd5, new byte[] { -65, -1, -1, -1 }),
			Map.entry(0x151, new byte[] { -90, -1, -1, -1 }),
			Map.entry(0x163, new byte[] { 0x67, -24, -4, -1, -1, -1 }),
			Map.entry(0x21e, new byte[] { 0x1d, -1, -1, -1 }));

		ObjectFile mainObjectFile = new ElfObjectFile(mainFile);
		ElfObjectFile exported = new ElfObjectFile(exportedFile);

		mainObjectFile.compareSectionBytes(".text", exported, ".text", text_patches);
		mainObjectFile.compareSectionBytes(".rodata", exported, ".rodata");
		mainObjectFile.compareSectionSizes(".rel.rodata", exported, ".rel.rodata");

		exported.hasSymbolAtAddress(".symtab", "sys_getpid", ".text", 0x00000000);
		exported.hasSymbolAtAddress(".symtab", "sys_kill", ".text", 0x00000008);
		exported.hasSymbolAtAddress(".symtab", "sys_write", ".text", 0x00000016);
		exported.hasSymbolAtAddress(".symtab", "_nolibc_memcpy_up", ".text", 0x0000002a);
		exported.hasSymbolAtAddress(".symtab", "fileno", ".text", 0x0000004a);
		exported.hasSymbolAtAddress(".symtab", "_start", ".text", 0x00000061);
		exported.hasSymbolAtAddress(".symtab", "write", ".text", 0x00000098);
		exported.hasSymbolAtAddress(".symtab", "fputc", ".text", 0x000000bc);
		exported.hasSymbolAtAddress(".symtab", "putchar", ".text", 0x000000f0);
		exported.hasSymbolAtAddress(".symtab", "print_number", ".text", 0x000000fb);
		exported.hasSymbolAtAddress(".symtab", "print_ascii_entry", ".text", 0x0000013f);
		exported.hasSymbolAtAddress(".symtab", "main", ".text", 0x000001cc);
		exported.hasSymbolAtAddress(".symtab", "s_ascii_properties", ".rodata", 0x00000000);
		exported.hasSymbolAtAddress(".symtab", "NUM_ASCII_PROPERTIES", ".rodata", 0x00000050);
		exported.hasSymbolAtAddress(".symtab", "COLUMNS", ".data", 0x00000000);

		exported.hasUndefinedSymbol(".symtab", "_auxv");
		exported.hasUndefinedSymbol(".symtab", "environ");
		exported.hasUndefinedSymbol(".symtab", "errno");
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

		exported.hasRelocationAtAddress(".rel.text", 0x00000053,
			X86_32_ElfRelocationType.R_386_32.typeId(), "errno", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x0000006a,
			X86_32_ElfRelocationType.R_386_32.typeId(), "environ", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x0000007c,
			X86_32_ElfRelocationType.R_386_32.typeId(), "_auxv", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000000b1,
			X86_32_ElfRelocationType.R_386_32.typeId(), "errno", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000165,
			X86_32_ElfRelocationType.R_386_PC32.typeId(), "isgraph", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000001fa,
			X86_32_ElfRelocationType.R_386_32.typeId(), "COLUMNS", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000215,
			X86_32_ElfRelocationType.R_386_32.typeId(), "s_ascii_properties", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000224,
			X86_32_ElfRelocationType.R_386_32.typeId(), "COLUMNS", 0);

		exported.hasRelocationAtAddress(".rel.rodata", 0x00000000,
			X86_32_ElfRelocationType.R_386_32.typeId(), "isgraph", 0);
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000008,
			X86_32_ElfRelocationType.R_386_32.typeId(), "isprint", 0);
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000010,
			X86_32_ElfRelocationType.R_386_32.typeId(), "iscntrl", 0);
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000018,
			X86_32_ElfRelocationType.R_386_32.typeId(), "isspace", 0);
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000020,
			X86_32_ElfRelocationType.R_386_32.typeId(), "ispunct", 0);
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000028,
			X86_32_ElfRelocationType.R_386_32.typeId(), "isalnum", 0);
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000030,
			X86_32_ElfRelocationType.R_386_32.typeId(), "isalpha", 0);
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000038,
			X86_32_ElfRelocationType.R_386_32.typeId(), "isdigit", 0);
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000040,
			X86_32_ElfRelocationType.R_386_32.typeId(), "isupper", 0);
		exported.hasRelocationAtAddress(".rel.rodata", 0x00000048,
			X86_32_ElfRelocationType.R_386_32.typeId(), "islower", 0);
	}

	@Test
	public void testExport_ctype_o() throws Exception {
		AddressFactory af = getProgram().getAddressFactory();
		AddressSetView set = af.getAddressSet(af.getAddress("0804924e"), af.getAddress("0804938e"))	// .text
				.union(af.getAddressSet(af.getAddress("0804a060"), af.getAddress("0804a160"))); 	// .rodata
		File exportedFile = exportObjectFile(set, new ElfRelocatableObjectExporter(), null);

		ObjectFile ctypeObjectFile = new ElfObjectFile(ctypeFile);
		ElfObjectFile exported = new ElfObjectFile(exportedFile);

		ctypeObjectFile.compareSectionBytes(".text", exported, ".text");
		ctypeObjectFile.compareSectionSizes(".rel.text", exported, ".rel.text");
		ctypeObjectFile.compareSectionBytes(".rodata", exported, ".rodata");

		exported.hasSymbolAtAddress(".symtab", "isalnum", ".text", 0x00000000);
		exported.hasSymbolAtAddress(".symtab", "isalpha", ".text", 0x0000001d);
		exported.hasSymbolAtAddress(".symtab", "iscntrl", ".text", 0x0000003a);
		exported.hasSymbolAtAddress(".symtab", "isdigit", ".text", 0x00000057);
		exported.hasSymbolAtAddress(".symtab", "isgraph", ".text", 0x00000074);
		exported.hasSymbolAtAddress(".symtab", "islower", ".text", 0x00000091);
		exported.hasSymbolAtAddress(".symtab", "isprint", ".text", 0x000000ae);
		exported.hasSymbolAtAddress(".symtab", "ispunct", ".text", 0x000000cd);
		exported.hasSymbolAtAddress(".symtab", "isspace", ".text", 0x000000ea);
		exported.hasSymbolAtAddress(".symtab", "isupper", ".text", 0x00000107);
		exported.hasSymbolAtAddress(".symtab", "isxdigit", ".text", 0x00000124);
		exported.hasSymbolAtAddress(".symtab", "_ctype_", ".rodata", 0x00000000);

		exported.hasRelocationAtAddress(".rel.text", 0x0000000f,
			X86_32_ElfRelocationType.R_386_32.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x0000002c,
			X86_32_ElfRelocationType.R_386_32.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000049,
			X86_32_ElfRelocationType.R_386_32.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000066,
			X86_32_ElfRelocationType.R_386_32.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000083,
			X86_32_ElfRelocationType.R_386_32.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000000a0,
			X86_32_ElfRelocationType.R_386_32.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000000bd,
			X86_32_ElfRelocationType.R_386_32.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000000dc,
			X86_32_ElfRelocationType.R_386_32.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x000000f9,
			X86_32_ElfRelocationType.R_386_32.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000116,
			X86_32_ElfRelocationType.R_386_32.typeId(), "_ctype_", 0);
		exported.hasRelocationAtAddress(".rel.text", 0x00000133,
			X86_32_ElfRelocationType.R_386_32.typeId(), "_ctype_", 0);
	}
}
