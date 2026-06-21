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
package ghidra.app.util.exporter.synthetic.coff.windows_msvc;

import static net.boricj.bft.coff.machines.amd64.CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32;
import static net.boricj.bft.coff.machines.amd64.CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32_1;
import static net.boricj.bft.coff.machines.amd64.CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32_2;
import static net.boricj.bft.coff.machines.amd64.CoffRelocationType_amd64.IMAGE_REL_AMD64_REL32_4;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;

import org.junit.Test;

import ghidra.DelinkerIntegrationTest;
import ghidra.app.util.exporter.CoffRelocatableObjectExporter;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import net.boricj.bft.coff.CoffFile;
import net.boricj.bft.coff.CoffRelocationTable;
import net.boricj.bft.coff.CoffSectionTable;
import net.boricj.bft.coff.CoffSymbolTable;
import net.boricj.bft.coff.constants.CoffMachine;
import net.boricj.bft.coff.sections.CoffBytes;

public class Rel32_N_Test extends DelinkerIntegrationTest {
	// Reference objects
	private static final File rel32_n_obj =
		new File("src/test/resources/synthetic/coff/windows-msvc/x64/rel32_n.obj");

	@Override
	protected String getProgramName() {
		return "src/test/resources/synthetic/coff/windows-msvc/x64/rel32_n.gzf";
	}

	@Test
	public void test_rel32_n_obj() throws Exception {
		// Expected file.
		CoffFile expected = new CoffFile.Parser(new FileInputStream(rel32_n_obj)).parse();

		CoffSectionTable expectedSections = expected.getSections();
		var expected_text_mn = findSectionByName(expectedSections, ".text$mn", CoffBytes.class);

		// Actual file.
		AddressRange range = getProgram().getMemory().getBlock(".text$mn").getAddressRange();
		AddressSetView set = getProgram().getAddressFactory()
				.getAddressSet(range.getMinAddress(), range.getMaxAddress());
		File exportedFile = exportObjectFile(set, new CoffRelocatableObjectExporter(), null);
		CoffFile actual = new CoffFile.Parser(new FileInputStream(exportedFile)).parse();

		// Header machine.
		assertHeader(actual.getHeader(), CoffMachine.IMAGE_FILE_MACHINE_AMD64);

		CoffSectionTable actSections = actual.getSections();
		var actual_text_mn = findSectionByName(actSections, ".text$mn", CoffBytes.class);

		CoffRelocationTable actual_rel_text_mn = actual_text_mn.getRelocations();
		CoffSymbolTable actual_symtab = actual.getSymbols();

		// Section flags.
		assertTrue(actual_text_mn.getCharacteristics().isCntCode());
		assertTrue(actual_text_mn.getCharacteristics().isMemExecute());
		assertTrue(actual_text_mn.getCharacteristics().isMemRead());
		assertFalse(actual_text_mn.getCharacteristics().isMemWrite());

		// Relocations.
		assertRel(actual_rel_text_mn, actual_symtab, 0x00000002,
			IMAGE_REL_AMD64_REL32, "target_symbol");
		assertRel(actual_rel_text_mn, actual_symtab, 0x00000009,
			IMAGE_REL_AMD64_REL32, "target_symbol");
		assertRel(actual_rel_text_mn, actual_symtab, 0x0000000f,
			IMAGE_REL_AMD64_REL32_1, "target_symbol");
		assertRel(actual_rel_text_mn, actual_symtab, 0x00000017,
			IMAGE_REL_AMD64_REL32_1, "target_symbol");
		assertRel(actual_rel_text_mn, actual_symtab, 0x0000001f,
			IMAGE_REL_AMD64_REL32_2, "target_symbol");
		assertRel(actual_rel_text_mn, actual_symtab, 0x00000028,
			IMAGE_REL_AMD64_REL32_2, "target_symbol");
		assertRel(actual_rel_text_mn, actual_symtab, 0x00000030,
			IMAGE_REL_AMD64_REL32_4, "target_symbol");
		assertRel(actual_rel_text_mn, actual_symtab, 0x0000003a,
			IMAGE_REL_AMD64_REL32_4, "target_symbol");

		// Section bytes match.
		assertSectionBytes(expected_text_mn, actual_text_mn);
	}
}
