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

import static net.boricj.bft.coff.constants.CoffStorageClass.IMAGE_SYM_CLASS_EXTERNAL;
import static net.boricj.bft.coff.machines.ppc.CoffRelocationType_ppc.IMAGE_REL_PPC_ADDR32;
import static net.boricj.bft.coff.machines.ppc.CoffRelocationType_ppc.IMAGE_REL_PPC_PAIR;
import static net.boricj.bft.coff.machines.ppc.CoffRelocationType_ppc.IMAGE_REL_PPC_REFHI;
import static net.boricj.bft.coff.machines.ppc.CoffRelocationType_ppc.IMAGE_REL_PPC_REFLO;
import static net.boricj.bft.coff.machines.ppc.CoffRelocationType_ppc.IMAGE_REL_PPC_REL24;
import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileInputStream;

import org.junit.Test;

import ghidra.DelinkerIntegrationTest;
import ghidra.app.util.exporter.CoffRelocatableObjectExporter;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import net.boricj.bft.coff.CoffFile;
import net.boricj.bft.coff.CoffRelocationTable;
import net.boricj.bft.coff.CoffSectionTable;
import net.boricj.bft.coff.CoffSymbolTable;
import net.boricj.bft.coff.sections.CoffBytes;

public class COFF_POWERPCBE_ascii_table_Test extends DelinkerIntegrationTest {
	private static final File mainFile =
		new File("src/test/resources/ascii-table/reference/coff_xbox360/powerpcbe/main.obj");

	@Override
	protected String getProgramName() {
		return "src/test/resources/ascii-table/reference/coff_xbox360/powerpcbe/ascii-table.exe.gzf";
	}

	@Test
	public void test_main_obj() throws Exception {
		// Expected file.
		CoffFile expected = new CoffFile.Parser(new FileInputStream(mainFile)).parse();

		CoffSectionTable expectedSections = expected.getSections();
		var expected_text = findSectionByName(expectedSections, ".text", CoffBytes.class);
		var expected_rdata = findSectionByName(expectedSections, ".rdata", CoffBytes.class);
		var expected_data = findSectionByName(expectedSections, ".data", CoffBytes.class);

		// Actual file. Keep explicit address ranges because this GZF has no program tree.
		AddressFactory af = getProgram().getAddressFactory();
		AddressSetView set = af
				.getAddressSet(af.getAddress("82010000"), af.getAddress("820102d3")) // .text
				.union(af.getAddressSet(af.getAddress("820004e0"), af.getAddress("82000537"))) // .rdata
				.union(af.getAddressSet(af.getAddress("82020040"), af.getAddress("82020043"))); // .data
		File exportedFile = exportObjectFile(set, new CoffRelocatableObjectExporter(), null);
		CoffFile actual = new CoffFile.Parser(new FileInputStream(exportedFile)).parse();

		assertEquals(expected.getHeader().getMachine(), actual.getHeader().getMachine());

		CoffSectionTable actualSections = actual.getSections();
		var actual_text = findSectionByName(actualSections, ".text", CoffBytes.class);
		var actual_rdata = findSectionByName(actualSections, ".rdata", CoffBytes.class);
		var actual_data = findSectionByName(actualSections, ".data", CoffBytes.class);

		CoffRelocationTable actual_rel_text = actual_text.getRelocations();
		CoffRelocationTable actual_rel_rdata = actual_rdata.getRelocations();
		CoffSymbolTable actual_symtab = actual.getSymbols();

		short actual_text_index = sectionNumber(actualSections, actual_text);
		short actual_rdata_index = sectionNumber(actualSections, actual_rdata);
		short actual_data_index = sectionNumber(actualSections, actual_data);

		// Defined symbols.
		assertSymbol(actual_symtab, actual_text_index, 0x00000000, "print_number",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000098, "print_ascii_entry",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_text_index, 0x00000198, "main",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_rdata_index, 0x00000000, "NUM_ASCII_PROPERTIES",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_rdata_index, 0x00000008, "s_ascii_properties",
			IMAGE_SYM_CLASS_EXTERNAL);
		assertSymbol(actual_symtab, actual_data_index, 0x00000000, "COLUMNS",
			IMAGE_SYM_CLASS_EXTERNAL);

		// Undefined symbols.
		assertUndefined(actual_symtab, "putchar");
		assertUndefined(actual_symtab, "__pctype_func");
		assertUndefined(actual_symtab, "isalnum");
		assertUndefined(actual_symtab, "isalpha");
		assertUndefined(actual_symtab, "iscntrl");
		assertUndefined(actual_symtab, "isdigit");
		assertUndefined(actual_symtab, "isgraph");
		assertUndefined(actual_symtab, "islower");
		assertUndefined(actual_symtab, "isprint");
		assertUndefined(actual_symtab, "ispunct");
		assertUndefined(actual_symtab, "isspace");
		assertUndefined(actual_symtab, "isupper");

		// .text relocations (REL24 calls).
		assertRel(actual_rel_text, actual_symtab, 0x0000006c, IMAGE_REL_PPC_REL24, "putchar");
		assertRel(actual_rel_text, actual_symtab, 0x00000080, IMAGE_REL_PPC_REL24, "putchar");
		assertRel(actual_rel_text, actual_symtab, 0x000000b8, IMAGE_REL_PPC_REL24,
			"print_number");
		assertRel(actual_rel_text, actual_symtab, 0x000000c0, IMAGE_REL_PPC_REL24, "putchar");
		assertRel(actual_rel_text, actual_symtab, 0x000000c4, IMAGE_REL_PPC_REL24,
			"__pctype_func");
		assertRel(actual_rel_text, actual_symtab, 0x000000f0, IMAGE_REL_PPC_REL24, "putchar");
		assertRel(actual_rel_text, actual_symtab, 0x000000fc, IMAGE_REL_PPC_REL24, "putchar");
		assertRel(actual_rel_text, actual_symtab, 0x00000104, IMAGE_REL_PPC_REL24, "putchar");
		assertRel(actual_rel_text, actual_symtab, 0x00000170, IMAGE_REL_PPC_REL24, "putchar");
		assertRel(actual_rel_text, actual_symtab, 0x0000017c, IMAGE_REL_PPC_REL24, "putchar");
		assertRel(actual_rel_text, actual_symtab, 0x0000026c, IMAGE_REL_PPC_REL24,
			"print_ascii_entry");
		assertRel(actual_rel_text, actual_symtab, 0x000002b8, IMAGE_REL_PPC_REL24, "putchar");

		// .text relocations (REFHI/REFLO with PAIR entries).
		assertRels(actual_rel_text, actual_symtab,
			new Rel(0x000001cc, IMAGE_REL_PPC_REFHI, "COLUMNS"),
			new Rel(0x000001cc, IMAGE_REL_PPC_PAIR, 0),
			new Rel(0x000001d0, IMAGE_REL_PPC_REFLO, "COLUMNS"),
			new Rel(0x000001d0, IMAGE_REL_PPC_PAIR, 0));
		assertRels(actual_rel_text, actual_symtab,
			new Rel(0x000001fc, IMAGE_REL_PPC_REFHI, "COLUMNS"),
			new Rel(0x000001fc, IMAGE_REL_PPC_PAIR, 0),
			new Rel(0x00000200, IMAGE_REL_PPC_REFLO, "COLUMNS"),
			new Rel(0x00000200, IMAGE_REL_PPC_PAIR, 0));
		assertRels(actual_rel_text, actual_symtab,
			new Rel(0x00000228, IMAGE_REL_PPC_REFHI, "COLUMNS"),
			new Rel(0x00000228, IMAGE_REL_PPC_PAIR, 0),
			new Rel(0x0000022c, IMAGE_REL_PPC_REFLO, "COLUMNS"),
			new Rel(0x0000022c, IMAGE_REL_PPC_PAIR, 0));
		assertRels(actual_rel_text, actual_symtab,
			new Rel(0x00000254, IMAGE_REL_PPC_REFHI, "NUM_ASCII_PROPERTIES"),
			new Rel(0x00000254, IMAGE_REL_PPC_PAIR, 0),
			new Rel(0x00000258, IMAGE_REL_PPC_REFLO, "NUM_ASCII_PROPERTIES"),
			new Rel(0x00000258, IMAGE_REL_PPC_PAIR, 0));
		assertRels(actual_rel_text, actual_symtab,
			new Rel(0x0000025c, IMAGE_REL_PPC_REFHI, "s_ascii_properties"),
			new Rel(0x0000025c, IMAGE_REL_PPC_PAIR, 0),
			new Rel(0x00000260, IMAGE_REL_PPC_REFLO, "s_ascii_properties"),
			new Rel(0x00000260, IMAGE_REL_PPC_PAIR, 0));
		assertRels(actual_rel_text, actual_symtab,
			new Rel(0x00000274, IMAGE_REL_PPC_REFHI, "COLUMNS"),
			new Rel(0x00000274, IMAGE_REL_PPC_PAIR, 0),
			new Rel(0x00000278, IMAGE_REL_PPC_REFLO, "COLUMNS"),
			new Rel(0x00000278, IMAGE_REL_PPC_PAIR, 0));
		assertRels(actual_rel_text, actual_symtab,
			new Rel(0x0000029c, IMAGE_REL_PPC_REFHI, "COLUMNS"),
			new Rel(0x0000029c, IMAGE_REL_PPC_PAIR, 0),
			new Rel(0x000002a0, IMAGE_REL_PPC_REFLO, "COLUMNS"),
			new Rel(0x000002a0, IMAGE_REL_PPC_PAIR, 0));
		assertEquals(40, actual_rel_text.size());

		// .rdata relocations.
		assertRel(actual_rel_rdata, actual_symtab, 0x00000008, IMAGE_REL_PPC_ADDR32, "isgraph");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000010, IMAGE_REL_PPC_ADDR32, "isprint");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000018, IMAGE_REL_PPC_ADDR32, "iscntrl");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000020, IMAGE_REL_PPC_ADDR32, "isspace");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000028, IMAGE_REL_PPC_ADDR32, "ispunct");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000030, IMAGE_REL_PPC_ADDR32, "isalnum");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000038, IMAGE_REL_PPC_ADDR32, "isalpha");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000040, IMAGE_REL_PPC_ADDR32, "isdigit");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000048, IMAGE_REL_PPC_ADDR32, "isupper");
		assertRel(actual_rel_rdata, actual_symtab, 0x00000050, IMAGE_REL_PPC_ADDR32, "islower");
		assertEquals(10, actual_rel_rdata.size());

		// Section bytes.
		assertSectionBytes(expected_text, actual_text);
		assertSectionBytes(expected_rdata, actual_rdata);
		assertSectionBytes(expected_data, actual_data);
	}
}
