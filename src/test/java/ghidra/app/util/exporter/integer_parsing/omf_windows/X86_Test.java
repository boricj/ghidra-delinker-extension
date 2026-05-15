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
package ghidra.app.util.exporter.integer_parsing.omf_windows;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;

import org.junit.Test;

import ghidra.DelinkerIntegrationTest;
import ghidra.app.util.exporter.OmfRelocatableObjectExporter;
import ghidra.program.model.address.AddressSetView;
import net.boricj.bft.omf.OmfFile;

public class X86_Test extends DelinkerIntegrationTest {

	private static final File main_file = new File(
		"src/test/resources/programs/integer-parsing/reference/omf/windows-borland/x86/main.obj");

	private static final File digits_file = new File(
		"src/test/resources/programs/integer-parsing/reference/omf/windows-borland/x86/digits.obj");

	@Override
	protected String getProgramName() {
		return "src/test/resources/programs/integer-parsing/reference/omf/windows-borland/x86/integer-parsing.exe.gzf";
	}

	@Test
	public void test_main_obj() throws Exception {
		// Expected file.
		OmfFile expected = new OmfFile.Parser(new FileInputStream(main_file)).parse();
		var expected_text = segmentDataByName(expected, "_TEXT");
		var expected_data = segmentDataByName(expected, "_DATA");

		// Actual file.
		AddressSetView set = findProgramModule("Object Files", "main.obj");
		File exportedFile = exportObjectFile(set, new OmfRelocatableObjectExporter(), null);
		OmfFile actual = new OmfFile.Parser(new FileInputStream(exportedFile)).parse();
		var actual_text = segmentDataByName(actual, ".text");
		var actual_data = segmentDataByName(actual, ".data");
		var actual_text_fixups = omfFixupSpecs(actual, ".text");
		var actual_data_fixups = omfFixupSpecs(actual, ".data");

		// Defined symbols.
		assertPublicSymbol(actual, ".data", "_s_ascii_digit_bias", 0x0);
		assertPublicSymbol(actual, ".text", "_parse_integer", 0x0);
		assertPublicSymbol(actual, ".text", "_main", 0x38);

		// Undefined symbols.
		assertExternalSymbol(actual, "_s_digits");
		assertExternalSymbol(actual, "_puts");
		assertEquals(2, externalSymbolNames(actual).size());

		// Segment bytes.
		assertSegmentBytes(expected_text, actual_text);
		assertSegmentBytes(expected_data, actual_data);

		// .text relocations.
		assertOmfFixups(actual_text_fixups,
			new OmfFixupDescriptor(0x13, true, "S:data"),
			new OmfFixupDescriptor(0x39, true, "S:data"),
			new OmfFixupDescriptor(0x4e, true, "S:data"),
			new OmfFixupDescriptor(0x64, true, "S:data"),
			new OmfFixupDescriptor(0x7c, true, "S:data"),
			new OmfFixupDescriptor(0x81, false, "E:_puts"));

		// .data relocations.
		assertOmfFixups(actual_data_fixups,
			new OmfFixupDescriptor(0x00, true, "E:_s_digits"));

		// SEGDEF attributes.
		assertSegdefIsDwordPublicUse32(actual, ".text");
		assertSegdefIsDwordPublicUse32(actual, ".data");
	}

	@Test
	public void test_digits_obj() throws Exception {
		// Expected file.
		OmfFile expected = new OmfFile.Parser(new FileInputStream(digits_file)).parse();
		var expected_data = segmentDataByName(expected, "_DATA");

		// Actual file.
		AddressSetView set = findProgramModule("Object Files", "digits.obj");
		File exportedFile = exportObjectFile(set, new OmfRelocatableObjectExporter(), null);
		OmfFile actual = new OmfFile.Parser(new FileInputStream(exportedFile)).parse();
		var actual_data = segmentDataByName(actual, ".data");
		var actual_data_fixups = omfFixupSpecs(actual, ".data");

		// Defined symbols.
		assertPublicSymbol(actual, ".data", "_s_digits", 0x0);

		// Undefined symbols.
		assertTrue(externalSymbolNames(actual).isEmpty());

		// Segment bytes.
		assertSegmentBytes(expected_data, actual_data);

		// .data relocations.
		assertOmfFixups(actual_data_fixups);

		// SEGDEF attributes.
		assertSegdefIsDwordPublicUse32(actual, ".data");
	}

}
