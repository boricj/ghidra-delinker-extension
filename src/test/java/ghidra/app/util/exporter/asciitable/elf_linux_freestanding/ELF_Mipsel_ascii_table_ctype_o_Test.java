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
import ghidra.app.util.bin.format.elf.relocation.MIPS_ElfRelocationType;
import ghidra.app.util.exporter.ElfRelocatableObjectExporter;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;

public class ELF_Mipsel_ascii_table_ctype_o_Test extends DelinkerIntegrationTest {
	private static final File ctypeFile =
		new File("src/test/resources/ascii-table/reference/elf_linux_freestanding/mipsel/ctype.o");

	@Override
	protected String getProgramName() {
		return "src/test/resources/ascii-table/reference/elf_linux_freestanding/mipsel/ascii-table.elf.gzf";
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
