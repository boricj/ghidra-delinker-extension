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
package ghidra.app.util.exporter.asciitable.coff_xbox360;

import java.io.File;

import org.junit.Test;

import ghidra.DelinkerIntegrationTest;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.app.util.exporter.CoffRelocatableObjectExporter;
import net.boricj.bft.coff.machines.powerpcbe.CoffRelocationType_powerpcbe;

public class COFF_POWERPCBE_ascii_table_Test extends DelinkerIntegrationTest {
	private static final File mainFile =
		new File("src/test/resources/ascii-table/reference/coff_xbox360/powerpcbe/main.obj");

	@Override
	protected String getProgramName() {
		return "src/test/resources/ascii-table/reference/coff_xbox360/powerpcbe/ascii-table.exe.gzf";
	}

	@Test
	public void testExport_main_o() throws Exception {
		AddressFactory af = getProgram().getAddressFactory();
		AddressSetView set = af
				.getAddressSet(af.getAddress("82010000"), af.getAddress("820102d3")) // .text
				.union(af.getAddressSet(af.getAddress("820004e0"), af.getAddress("82000537"))) // .rdata
				.union(af.getAddressSet(af.getAddress("82020040"), af.getAddress("82020043"))); // .data
		File exportedFile = exportObjectFile(set, new CoffRelocatableObjectExporter(), null);

		ObjectFile mainObjectFile = new CoffObjectFile(mainFile);
		CoffObjectFile exported = new CoffObjectFile(exportedFile);

		mainObjectFile.compareSectionBytes(".text", exported, ".text");
		mainObjectFile.compareSectionBytes(".rdata", exported, ".rdata");
		mainObjectFile.compareSectionBytes(".data", exported, ".data");

		exported.hasSymbolAtAddress("print_number", ".text", 0x00000000);
		exported.hasSymbolAtAddress("print_ascii_entry", ".text", 0x00000098);
		exported.hasSymbolAtAddress("main", ".text", 0x00000198);
		exported.hasSymbolAtAddress("NUM_ASCII_PROPERTIES", ".rdata", 0x00000000);
		exported.hasSymbolAtAddress("s_ascii_properties", ".rdata", 0x00000008);
		exported.hasSymbolAtAddress("COLUMNS", ".data", 0x00000000);

		exported.hasUndefinedSymbol("putchar");
		exported.hasUndefinedSymbol("__pctype_func");
		exported.hasUndefinedSymbol("isalnum");
		exported.hasUndefinedSymbol("isalpha");
		exported.hasUndefinedSymbol("iscntrl");
		exported.hasUndefinedSymbol("isdigit");
		exported.hasUndefinedSymbol("isgraph");
		exported.hasUndefinedSymbol("islower");
		exported.hasUndefinedSymbol("isprint");
		exported.hasUndefinedSymbol("ispunct");
		exported.hasUndefinedSymbol("isspace");
		exported.hasUndefinedSymbol("isupper");

		exported.hasRelocationAtAddress(".text", 0x0000006c,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REL24, "putchar");
		exported.hasRelocationAtAddress(".text", 0x00000080,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REL24, "putchar");
		exported.hasRelocationAtAddress(".text", 0x000000b8,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REL24, "print_number");
		exported.hasRelocationAtAddress(".text", 0x000000c0,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REL24, "putchar");
		exported.hasRelocationAtAddress(".text", 0x000000c4,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REL24, "__pctype_func");
		exported.hasRelocationAtAddress(".text", 0x000000f0,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REL24, "putchar");
		exported.hasRelocationAtAddress(".text", 0x000000fc,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REL24, "putchar");
		exported.hasRelocationAtAddress(".text", 0x00000104,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REL24, "putchar");
		exported.hasRelocationAtAddress(".text", 0x00000170,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REL24, "putchar");
		exported.hasRelocationAtAddress(".text", 0x0000017c,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REL24, "putchar");
		exported.hasRelocationAtAddress(".text", 0x0000026c,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REL24, "print_ascii_entry");
		exported.hasRelocationAtAddress(".text", 0x000002b8,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REL24, "putchar");

		exported.hasRelocationAtAddress(".text", 0x000001cc,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REFHI, "COLUMNS");
		exported.hasRelocationAtAddress(".text", 0x000001cc,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_PAIR, 0);
		exported.hasRelocationAtAddress(".text", 0x000001d0,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REFLO, "COLUMNS");
		exported.hasRelocationAtAddress(".text", 0x000001d0,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_PAIR, 0);
		exported.hasRelocationAtAddress(".text", 0x000001fc,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REFHI, "COLUMNS");
		exported.hasRelocationAtAddress(".text", 0x000001fc,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_PAIR, 0);
		exported.hasRelocationAtAddress(".text", 0x00000200,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REFLO, "COLUMNS");
		exported.hasRelocationAtAddress(".text", 0x00000200,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_PAIR, 0);
		exported.hasRelocationAtAddress(".text", 0x00000228,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REFHI, "COLUMNS");
		exported.hasRelocationAtAddress(".text", 0x00000228,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_PAIR, 0);
		exported.hasRelocationAtAddress(".text", 0x0000022c,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REFLO, "COLUMNS");
		exported.hasRelocationAtAddress(".text", 0x0000022c,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_PAIR, 0);
		exported.hasRelocationAtAddress(".text", 0x00000254,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REFHI, "NUM_ASCII_PROPERTIES");
		exported.hasRelocationAtAddress(".text", 0x00000254,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_PAIR, 0);
		exported.hasRelocationAtAddress(".text", 0x00000258,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REFLO, "NUM_ASCII_PROPERTIES");
		exported.hasRelocationAtAddress(".text", 0x00000258,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_PAIR, 0);
		exported.hasRelocationAtAddress(".text", 0x0000025c,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REFHI, "s_ascii_properties");
		exported.hasRelocationAtAddress(".text", 0x0000025c,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_PAIR, 0);
		exported.hasRelocationAtAddress(".text", 0x00000260,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REFLO, "s_ascii_properties");
		exported.hasRelocationAtAddress(".text", 0x00000260,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_PAIR, 0);
		exported.hasRelocationAtAddress(".text", 0x00000274,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REFHI, "COLUMNS");
		exported.hasRelocationAtAddress(".text", 0x00000274,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_PAIR, 0);
		exported.hasRelocationAtAddress(".text", 0x00000278,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REFLO, "COLUMNS");
		exported.hasRelocationAtAddress(".text", 0x00000278,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_PAIR, 0);
		exported.hasRelocationAtAddress(".text", 0x0000029c,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REFHI, "COLUMNS");
		exported.hasRelocationAtAddress(".text", 0x0000029c,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_PAIR, 0);
		exported.hasRelocationAtAddress(".text", 0x000002a0,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_REFLO, "COLUMNS");
		exported.hasRelocationAtAddress(".text", 0x000002a0,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_PAIR, 0);

		exported.hasRelocationAtAddress(".rdata", 0x00000008,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_ADDR32, "isgraph");
		exported.hasRelocationAtAddress(".rdata", 0x00000010,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_ADDR32, "isprint");
		exported.hasRelocationAtAddress(".rdata", 0x00000018,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_ADDR32, "iscntrl");
		exported.hasRelocationAtAddress(".rdata", 0x00000020,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_ADDR32, "isspace");
		exported.hasRelocationAtAddress(".rdata", 0x00000028,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_ADDR32, "ispunct");
		exported.hasRelocationAtAddress(".rdata", 0x00000030,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_ADDR32, "isalnum");
		exported.hasRelocationAtAddress(".rdata", 0x00000038,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_ADDR32, "isalpha");
		exported.hasRelocationAtAddress(".rdata", 0x00000040,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_ADDR32, "isdigit");
		exported.hasRelocationAtAddress(".rdata", 0x00000048,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_ADDR32, "isupper");
		exported.hasRelocationAtAddress(".rdata", 0x00000050,
			CoffRelocationType_powerpcbe.IMAGE_REL_PPC_ADDR32, "islower");
	}
}
