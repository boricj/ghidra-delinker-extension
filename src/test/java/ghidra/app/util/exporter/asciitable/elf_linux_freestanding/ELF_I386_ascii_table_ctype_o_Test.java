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

import org.junit.Test;

import ghidra.DelinkerIntegrationTest;
import ghidra.app.util.bin.format.elf.relocation.X86_32_ElfRelocationType;
import ghidra.app.util.exporter.ElfRelocatableObjectExporter;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;

public class ELF_I386_ascii_table_ctype_o_Test extends DelinkerIntegrationTest {
	private static final File ctypeFile =
		new File("src/test/resources/ascii-table/reference/elf_linux_freestanding/i386/ctype.o");

	@Override
	protected String getProgramName() {
		return "src/test/resources/ascii-table/reference/elf_linux_freestanding/i386/ascii-table.elf.gzf";
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
