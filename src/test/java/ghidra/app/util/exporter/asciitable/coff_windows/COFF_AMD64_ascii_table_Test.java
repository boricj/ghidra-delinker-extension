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
package ghidra.app.util.exporter.asciitable.coff_windows;

import java.io.File;

import org.junit.Test;

import ghidra.DelinkerIntegrationTest;
import ghidra.app.util.exporter.CoffRelocatableObjectExporter;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import net.boricj.bft.coff.machines.amd64.CoffRelocationType_amd64;

public class COFF_AMD64_ascii_table_Test extends DelinkerIntegrationTest {
	private static final File mainFile =
		new File("src/test/resources/ascii-table/reference/coff_windows/amd64/main.obj");

	@Override
	protected String getProgramName() {
		return "src/test/resources/ascii-table/reference/coff_windows/amd64/ascii-table.exe.gzf";
	}

	@Test
	public void testExport_main_o() throws Exception {
		AddressFactory af = getProgram().getAddressFactory();
		AddressSetView set = af
				.getAddressSet(af.getAddress("1400073b0"), af.getAddress("1400075c5"))	// .text
				.union(af.getAddressSet(af.getAddress("14009e000"), af.getAddress("14009e003")))	 	// .data
				.union(af.getAddressSet(af.getAddress("140087f20"), af.getAddress("140087fcf"))); 	// .rdata
		File exportedFile = exportObjectFile(set, new CoffRelocatableObjectExporter(), null);

		ObjectFile mainObjectFile = new CoffObjectFile(mainFile);
		CoffObjectFile exported = new CoffObjectFile(exportedFile);

		mainObjectFile.compareSectionBytes(".text$mn", exported, ".text");
		mainObjectFile.compareSectionBytes(".data", exported, ".data");
		mainObjectFile.compareSectionBytes(".rdata", exported, ".rdata");

		exported.hasSymbolAtAddress("_print_number", ".text", 0x00000000);
		exported.hasSymbolAtAddress("_print_ascii_entry", ".text", 0x00000080);
		exported.hasSymbolAtAddress("_main", ".text", 0x00000160);
		exported.hasSymbolAtAddress("_NUM_ASCII_PROPERTIES", ".rdata", 0x00000000);
		exported.hasSymbolAtAddress("_s_ascii_properties", ".rdata", 0x00000010);
		exported.hasSymbolAtAddress("_COLUMNS", ".data", 0x00000000);

		exported.hasUndefinedSymbol("_putchar");
		exported.hasUndefinedSymbol("_isalnum");
		exported.hasUndefinedSymbol("_isalpha");
		exported.hasUndefinedSymbol("_iscntrl");
		exported.hasUndefinedSymbol("_isdigit");
		exported.hasUndefinedSymbol("_isgraph");
		exported.hasUndefinedSymbol("_islower");
		exported.hasUndefinedSymbol("_isprint");
		exported.hasUndefinedSymbol("_ispunct");
		exported.hasUndefinedSymbol("_isspace");
		exported.hasUndefinedSymbol("_isupper");

		exported.hasRelocationAtAddress(".text", 0x00000053,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32, "_putchar");
		exported.hasRelocationAtAddress(".text", 0x00000064,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32, "_putchar");
		exported.hasRelocationAtAddress(".text", 0x0000009A,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32, "_print_number");
		exported.hasRelocationAtAddress(".text", 0x000000A4,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32, "_putchar");
		exported.hasRelocationAtAddress(".text", 0x000000B0,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32, "_isgraph");
		exported.hasRelocationAtAddress(".text", 0x000000C0,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32, "_putchar");
		exported.hasRelocationAtAddress(".text", 0x000000CD,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32, "_putchar");
		exported.hasRelocationAtAddress(".text", 0x000000D8,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32, "_putchar");
		exported.hasRelocationAtAddress(".text", 0x00000132,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32, "_putchar");
		exported.hasRelocationAtAddress(".text", 0x0000013F,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32, "_putchar");
		exported.hasRelocationAtAddress(".text", 0x0000018D,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32, "_COLUMNS");
		exported.hasRelocationAtAddress(".text", 0x0000019E,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32, "_COLUMNS");
		exported.hasRelocationAtAddress(".text", 0x000001B1,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32, "_COLUMNS");
		exported.hasRelocationAtAddress(".text", 0x000001C0,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32, "_NUM_ASCII_PROPERTIES");
		exported.hasRelocationAtAddress(".text", 0x000001C7,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32, "_s_ascii_properties");
		exported.hasRelocationAtAddress(".text", 0x000001D1,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32, "_print_ascii_entry");
		exported.hasRelocationAtAddress(".text", 0x000001DC,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32, "_COLUMNS");
		exported.hasRelocationAtAddress(".text", 0x000001E4,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32, "_COLUMNS");
		exported.hasRelocationAtAddress(".text", 0x00000205,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32, "_putchar");

		exported.hasRelocationAtAddress(".rdata", 0x00000010,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_ADDR64, "_isgraph");
		exported.hasRelocationAtAddress(".rdata", 0x00000020,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_ADDR64, "_isprint");
		exported.hasRelocationAtAddress(".rdata", 0x00000030,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_ADDR64, "_iscntrl");
		exported.hasRelocationAtAddress(".rdata", 0x00000040,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_ADDR64, "_isspace");
		exported.hasRelocationAtAddress(".rdata", 0x00000050,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_ADDR64, "_ispunct");
		exported.hasRelocationAtAddress(".rdata", 0x00000060,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_ADDR64, "_isalnum");
		exported.hasRelocationAtAddress(".rdata", 0x00000070,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_ADDR64, "_isalpha");
		exported.hasRelocationAtAddress(".rdata", 0x00000080,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_ADDR64, "_isdigit");
		exported.hasRelocationAtAddress(".rdata", 0x00000090,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_ADDR64, "_isupper");
		exported.hasRelocationAtAddress(".rdata", 0x000000A0,
			CoffRelocationType_amd64.IMAGE_REL_AMD64_ADDR64, "_islower");
	}
}
