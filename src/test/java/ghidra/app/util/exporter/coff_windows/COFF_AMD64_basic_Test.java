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
package ghidra.app.util.exporter.coff_windows;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.FileInputStream;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.Test;

import ghidra.DelinkerIntegrationTest;
import ghidra.app.util.exporter.CoffRelocatableObjectExporter;
import ghidra.program.model.address.AddressSetView;
import net.boricj.bft.coff.CoffFile;
import net.boricj.bft.coff.CoffSection;
import net.boricj.bft.coff.CoffRelocationTable.CoffRel;
import net.boricj.bft.coff.constants.CoffMachine;
import net.boricj.bft.coff.constants.CoffRelocationType;

public class COFF_AMD64_basic_Test extends DelinkerIntegrationTest {
	private static final File mainFile =
		new File("src/test/resources/arch/x86_64_windows/reference/basic/main.obj");

	@Override
	protected String getProgramName() {
		return "src/test/resources/arch/x86_64_windows/reference/basic/basic.exe.gzf";
	}

	@Test
	public void testExport_main_obj() throws Exception {
		AddressSetView set = getAddressSetOfMemoryBlocks(getProgram(), List.of(".text", ".data"));
		File exportedFile = exportObjectFile(set, new CoffRelocatableObjectExporter(), null);

		ObjectFile mainObjectFile = new CoffObjectFile(mainFile);
		CoffObjectFile exported = new CoffObjectFile(exportedFile);
		mainObjectFile.getSectionBytes(".text");
		mainObjectFile.getSectionBytes(".data");
		exported.getSectionBytes(".text");
		exported.getSectionBytes(".data");

		CoffFile expected = parseCoff(mainFile);
		CoffFile actual = parseCoff(exportedFile);
		assertEquals(CoffMachine.IMAGE_FILE_MACHINE_AMD64, actual.getHeader().getMachine());

		assertRelocationOffsetsAndTypes(expected, actual, ".text");
		assertRelocationOffsetsAndTypes(expected, actual, ".data");
	}

	private static CoffFile parseCoff(File file) throws Exception {
		try (FileInputStream fis = new FileInputStream(file)) {
			return new CoffFile.Parser(fis).parse();
		}
	}

	private static void assertRelocationOffsetsAndTypes(CoffFile expected, CoffFile actual,
			String sectionName) {
		Map<Integer, CoffRelocationType> expectedRelocations = getSection(expected, sectionName)
				.getRelocations()
				.stream()
				.collect(Collectors.toMap(CoffRel::getVirtualAddress, CoffRel::getType));
		Map<Integer, CoffRelocationType> actualRelocations = getSection(actual, sectionName)
				.getRelocations()
				.stream()
				.collect(Collectors.toMap(CoffRel::getVirtualAddress, CoffRel::getType));

		assertEquals(expectedRelocations, actualRelocations);
	}

	private static CoffSection getSection(CoffFile coff, String sectionName) {
		CoffSection section = coff.getSections()
				.stream()
				.filter(s -> s.getName().equals(sectionName))
				.findFirst()
				.orElse(null);
		assertNotNull(section);
		return section;
	}
}
