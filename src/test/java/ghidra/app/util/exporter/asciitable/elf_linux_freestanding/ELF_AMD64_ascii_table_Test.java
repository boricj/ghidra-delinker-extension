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
import net.boricj.bft.elf.machines.amd64.ElfRelocationType_amd64;

public class ELF_AMD64_ascii_table_Test extends DelinkerIntegrationTest {
	private static final File mainFile =
		new File("src/test/resources/ascii-table/reference/elf_linux_freestanding/amd64/main.o");
	private static final File ctypeFile =
		new File("src/test/resources/ascii-table/reference/elf_linux_freestanding/amd64/ctype.o");

	@Override
	protected String getProgramName() {
		return "src/test/resources/ascii-table/reference/elf_linux_freestanding/amd64/ascii-table.elf.gzf";
	}

	@Test
	public void testExport_main_o() throws Exception {
		AddressFactory af = getProgram().getAddressFactory();
		AddressSetView set = af.getAddressSet(af.getAddress("00401000"), af.getAddress("00401137"))	// .text
				.union(af.getAddressSet(af.getAddress("00402000"), af.getAddress("004020a3"))) 	// .rodata
				.union(af.getAddressSet(af.getAddress("00403000"), af.getAddress("00403003")));	 	// .data
		File exportedFile = exportObjectFile(set, new ElfRelocatableObjectExporter(), null);

		Map<Integer, byte[]> text_patches = Map.ofEntries(
			Map.entry(0x5c, new byte[] { -96, -1, -1, -1 }),
			Map.entry(0x6d, new byte[] { 0x67, -24 }),
			Map.entry(0x114, new byte[] { 0x2e, -1, -1, -1 }));

		ElfObjectFile mainObjectFile = new ElfObjectFile(mainFile);
		ElfObjectFile exported = new ElfObjectFile(exportedFile);

		mainObjectFile.compareSectionBytes(".text", exported, ".text", text_patches);
		mainObjectFile.compareSectionBytes(".rodata", exported, ".rodata");
		mainObjectFile.compareSectionSizes(".rela.rodata", exported, ".rela.rodata");

		exported.hasSymbolAtAddress(".symtab", "print_number", ".text", 0x00000000);
		exported.hasSymbolAtAddress(".symtab", "print_ascii_entry", ".text", 0x00000046);
		exported.hasSymbolAtAddress(".symtab", "main", ".text", 0x000000d5);

		exported.hasSymbolAtAddress(".symtab", "COLUMNS", ".data", 0x00000000);

		exported.hasSymbolAtAddress(".symtab", "s_ascii_properties", ".rodata", 0x00000000);
		exported.hasSymbolAtAddress(".symtab", "NUM_ASCII_PROPERTIES", ".rodata", 0x000000a0);

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
		exported.hasUndefinedSymbol(".symtab", "putchar");

		exported.hasRelocationAtAddress(".rela.text", 0x0000000f,
			ElfRelocationType_amd64.R_X86_64_PC32, "putchar", -4);
		exported.hasRelocationAtAddress(".rela.text", 0x0000003d,
			ElfRelocationType_amd64.R_X86_64_PC32, "putchar", -4);
		/*exported.hasRelocationAtAddress(".rela.text", 0x0000005c,
			ElfRelocationType_amd64.R_X86_64_PC32, "print_number", -4);*/
		exported.hasRelocationAtAddress(".rela.text", 0x00000066,
			ElfRelocationType_amd64.R_X86_64_PC32, "putchar", -4);
		/*exported.hasRelocationAtAddress(".rela.text", 0x0000006f,
			ElfRelocationType_amd64.R_X86_64_PC32, "isgraph", -4);*/
		exported.hasRelocationAtAddress(".rela.text", 0x0000007b,
			ElfRelocationType_amd64.R_X86_64_PC32, "putchar", -4);
		exported.hasRelocationAtAddress(".rela.text", 0x00000085,
			ElfRelocationType_amd64.R_X86_64_PC32, "putchar", -4);
		exported.hasRelocationAtAddress(".rela.text", 0x00000096,
			ElfRelocationType_amd64.R_X86_64_PC32, "putchar", -4);
		exported.hasRelocationAtAddress(".rela.text", 0x000000a2,
			ElfRelocationType_amd64.R_X86_64_PC32, "putchar", -4);
		exported.hasRelocationAtAddress(".rela.text", 0x000000c6,
			ElfRelocationType_amd64.R_X86_64_PC32, "putchar", -4);
		exported.hasRelocationAtAddress(".rela.text", 0x000000e3,
			ElfRelocationType_amd64.R_X86_64_PC32, "putchar", -4);
		exported.hasRelocationAtAddress(".rela.text", 0x000000f1,
			ElfRelocationType_amd64.R_X86_64_PC32, "COLUMNS", -4);
		exported.hasRelocationAtAddress(".rela.text", 0x0000010f,
			/* ElfRelocationType_amd64.R_X86_64_32 */ ElfRelocationType_amd64.R_X86_64_32S,
			"s_ascii_properties", 0);
		/* exported.hasRelocationAtAddress(".rela.text", 0x00000114,
			ElfRelocationType_amd64.R_X86_64_PC32, "print_ascii_entry", -4); */
		exported.hasRelocationAtAddress(".rela.text", 0x0000011a,
			ElfRelocationType_amd64.R_X86_64_PC32, "COLUMNS", -4);

		exported.hasRelocationAtAddress(".rela.rodata", 0x00000000,
			ElfRelocationType_amd64.R_X86_64_64, "isgraph", 0);
		exported.hasRelocationAtAddress(".rela.rodata", 0x00000010,
			ElfRelocationType_amd64.R_X86_64_64, "isprint", 0);
		exported.hasRelocationAtAddress(".rela.rodata", 0x00000020,
			ElfRelocationType_amd64.R_X86_64_64, "iscntrl", 0);
		exported.hasRelocationAtAddress(".rela.rodata", 0x00000030,
			ElfRelocationType_amd64.R_X86_64_64, "isspace", 0);
		exported.hasRelocationAtAddress(".rela.rodata", 0x00000040,
			ElfRelocationType_amd64.R_X86_64_64, "ispunct", 0);
		exported.hasRelocationAtAddress(".rela.rodata", 0x00000050,
			ElfRelocationType_amd64.R_X86_64_64, "isalnum", 0);
		exported.hasRelocationAtAddress(".rela.rodata", 0x00000060,
			ElfRelocationType_amd64.R_X86_64_64, "isalpha", 0);
		exported.hasRelocationAtAddress(".rela.rodata", 0x00000070,
			ElfRelocationType_amd64.R_X86_64_64, "isdigit", 0);
		exported.hasRelocationAtAddress(".rela.rodata", 0x00000080,
			ElfRelocationType_amd64.R_X86_64_64, "isupper", 0);
		exported.hasRelocationAtAddress(".rela.rodata", 0x00000090,
			ElfRelocationType_amd64.R_X86_64_64, "islower", 0);
	}

	@Test
	public void testExport_ctype_o() throws Exception {
		AddressFactory af = getProgram().getAddressFactory();
		AddressSetView set = af.getAddressSet(af.getAddress("00401138"), af.getAddress("00401257"))	// .text
				.union(af.getAddressSet(af.getAddress("004020c0"), af.getAddress("004021c0"))); 	// .rodata
		File exportedFile = exportObjectFile(set, new ElfRelocatableObjectExporter(), null);

		ElfObjectFile ctypeObjectFile = new ElfObjectFile(ctypeFile);
		ElfObjectFile exported = new ElfObjectFile(exportedFile);

		ctypeObjectFile.compareSectionBytes(".text", exported, ".text");
		ctypeObjectFile.compareSectionSizes(".rela.text", exported, ".rela.text");
		ctypeObjectFile.compareSectionBytes(".rodata", exported, ".rodata");

		exported.hasSymbolAtAddress(".symtab", "isalnum", ".text", 0x00000000);
		exported.hasSymbolAtAddress(".symtab", "isalpha", ".text", 0x0000001a);
		exported.hasSymbolAtAddress(".symtab", "iscntrl", ".text", 0x00000034);
		exported.hasSymbolAtAddress(".symtab", "isdigit", ".text", 0x0000004e);
		exported.hasSymbolAtAddress(".symtab", "isgraph", ".text", 0x00000068);
		exported.hasSymbolAtAddress(".symtab", "islower", ".text", 0x00000082);
		exported.hasSymbolAtAddress(".symtab", "isprint", ".text", 0x0000009c);
		exported.hasSymbolAtAddress(".symtab", "ispunct", ".text", 0x000000b8);
		exported.hasSymbolAtAddress(".symtab", "isspace", ".text", 0x000000d2);
		exported.hasSymbolAtAddress(".symtab", "isupper", ".text", 0x000000ec);
		exported.hasSymbolAtAddress(".symtab", "isxdigit", ".text", 0x00000106);
		exported.hasSymbolAtAddress(".symtab", "_ctype_", ".rodata", 0x00000000);

		exported.hasRelocationAtAddress(".rela.text", 0x0000000c,
			ElfRelocationType_amd64.R_X86_64_32S, "_ctype_", 1);
		exported.hasRelocationAtAddress(".rela.text", 0x00000026,
			ElfRelocationType_amd64.R_X86_64_32S, "_ctype_", 1);
		exported.hasRelocationAtAddress(".rela.text", 0x00000040,
			ElfRelocationType_amd64.R_X86_64_32S, "_ctype_", 1);
		exported.hasRelocationAtAddress(".rela.text", 0x0000005a,
			ElfRelocationType_amd64.R_X86_64_32S, "_ctype_", 1);
		exported.hasRelocationAtAddress(".rela.text", 0x00000074,
			ElfRelocationType_amd64.R_X86_64_32S, "_ctype_", 1);
		exported.hasRelocationAtAddress(".rela.text", 0x0000008e,
			ElfRelocationType_amd64.R_X86_64_32S, "_ctype_", 1);
		exported.hasRelocationAtAddress(".rela.text", 0x000000a8,
			ElfRelocationType_amd64.R_X86_64_32S, "_ctype_", 1);
		exported.hasRelocationAtAddress(".rela.text", 0x000000c4,
			ElfRelocationType_amd64.R_X86_64_32S, "_ctype_", 1);
		exported.hasRelocationAtAddress(".rela.text", 0x000000de,
			ElfRelocationType_amd64.R_X86_64_32S, "_ctype_", 1);
		exported.hasRelocationAtAddress(".rela.text", 0x000000f8,
			ElfRelocationType_amd64.R_X86_64_32S, "_ctype_", 1);
		exported.hasRelocationAtAddress(".rela.text", 0x00000112,
			ElfRelocationType_amd64.R_X86_64_32S, "_ctype_", 1);
	}
}
