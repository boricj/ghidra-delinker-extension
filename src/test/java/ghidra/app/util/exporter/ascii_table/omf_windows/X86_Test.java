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
package ghidra.app.util.exporter.ascii_table.omf_windows;

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
	private static final File main_file =
		new File(
			"src/test/resources/programs/ascii-table/reference/omf/windows-borland/x86/main.obj");

	private static final File openbsd_ctype_file =
		new File(
			"src/test/resources/programs/ascii-table/reference/omf/windows-borland/x86/openbsd_ctype.obj");

	@Override
	protected String getProgramName() {
		return "src/test/resources/programs/ascii-table/reference/omf/windows-borland/x86/ascii-table.exe.gzf";
	}

	@Test
	public void test_main_obj() throws Exception {
		// Expected file.
		OmfFile expected = new OmfFile.Parser(new FileInputStream(main_file)).parse();
		findSegmentByName(expected, "_TEXT");
		findSegmentByName(expected, "_DATA");
		var expected_text = segmentDataByName(expected, "_TEXT");
		var expected_data = segmentDataByName(expected, "_DATA");

		// Actual file.
		AddressSetView set = findProgramModule("Object Files", "main.obj");
		File exportedFile = exportObjectFile(set, new OmfRelocatableObjectExporter(), null);
		OmfFile actual = new OmfFile.Parser(new FileInputStream(exportedFile)).parse();
		findSegmentByName(actual, ".text");
		findSegmentByName(actual, ".data");
		var actual_text = segmentDataByName(actual, ".text");
		var actual_data = segmentDataByName(actual, ".data");
		var actual_text_fixups = omfFixupSpecs(actual, ".text");
		var actual_data_fixups = omfFixupSpecs(actual, ".data");

		// Defined symbols.
		assertPublicSymbol(actual, ".text", "_print_number", 0x0000);
		assertPublicSymbol(actual, ".text", "_print_ascii_entry", 0x00a0);
		assertPublicSymbol(actual, ".text", "_main", 0x01e7);
		assertPublicSymbol(actual, ".data", "_NUM_ASCII_PROPERTIES", 0x0000);
		assertPublicSymbol(actual, ".data", "_s_ascii_properties", 0x0004);
		assertPublicSymbol(actual, ".data", "_COLUMNS", 0x0054);

		// Undefined/external symbols.
		assertExternalSymbol(actual, "__streams");
		assertExternalSymbol(actual, "_openbsd_isgraph");
		assertExternalSymbol(actual, "_openbsd_isprint");
		assertExternalSymbol(actual, "_openbsd_iscntrl");
		assertExternalSymbol(actual, "_openbsd_isspace");
		assertExternalSymbol(actual, "_openbsd_ispunct");
		assertExternalSymbol(actual, "_openbsd_isalnum");
		assertExternalSymbol(actual, "_openbsd_isalpha");
		assertExternalSymbol(actual, "_openbsd_isdigit");
		assertExternalSymbol(actual, "_openbsd_isupper");
		assertExternalSymbol(actual, "_openbsd_islower");
		assertExternalSymbol(actual, "__fputc");
		assertEquals(12, externalSymbolNames(actual).size());

		// Segment bytes.
		assertSegmentBytes(expected_text, actual_text);
		assertSegmentBytes(expected_data, actual_data);

		// .text relocations.
		assertOmfFixups(actual_text_fixups,
			new OmfFixupDescriptor(0x02f, true, "E:__streams"),
			new OmfFixupDescriptor(0x036, true, "E:__streams"),
			new OmfFixupDescriptor(0x049, true, "E:__streams"),
			new OmfFixupDescriptor(0x055, false, "E:__fputc"),
			new OmfFixupDescriptor(0x060, true, "E:__streams"),
			new OmfFixupDescriptor(0x067, true, "E:__streams"),
			new OmfFixupDescriptor(0x07d, true, "E:__streams"),
			new OmfFixupDescriptor(0x088, false, "E:__fputc"),
			new OmfFixupDescriptor(0x0b3, true, "E:__streams"),
			new OmfFixupDescriptor(0x0ba, true, "E:__streams"),
			new OmfFixupDescriptor(0x0c8, true, "E:__streams"),
			new OmfFixupDescriptor(0x0cf, false, "E:__fputc"),
			new OmfFixupDescriptor(0x0dc, false, "E:_openbsd_isgraph"),
			new OmfFixupDescriptor(0x0e7, true, "E:__streams"),
			new OmfFixupDescriptor(0x0ee, true, "E:__streams"),
			new OmfFixupDescriptor(0x0fe, true, "E:__streams"),
			new OmfFixupDescriptor(0x107, false, "E:__fputc"),
			new OmfFixupDescriptor(0x112, true, "E:__streams"),
			new OmfFixupDescriptor(0x119, true, "E:__streams"),
			new OmfFixupDescriptor(0x127, true, "E:__streams"),
			new OmfFixupDescriptor(0x12e, false, "E:__fputc"),
			new OmfFixupDescriptor(0x137, true, "E:__streams"),
			new OmfFixupDescriptor(0x13e, true, "E:__streams"),
			new OmfFixupDescriptor(0x14c, true, "E:__streams"),
			new OmfFixupDescriptor(0x153, false, "E:__fputc"),
			new OmfFixupDescriptor(0x184, true, "E:__streams"),
			new OmfFixupDescriptor(0x18b, true, "E:__streams"),
			new OmfFixupDescriptor(0x19e, true, "E:__streams"),
			new OmfFixupDescriptor(0x1aa, false, "E:__fputc"),
			new OmfFixupDescriptor(0x1b5, true, "E:__streams"),
			new OmfFixupDescriptor(0x1bc, true, "E:__streams"),
			new OmfFixupDescriptor(0x1ca, true, "E:__streams"),
			new OmfFixupDescriptor(0x1d1, false, "E:__fputc"),
			new OmfFixupDescriptor(0x1f8, true, "S:data"),
			new OmfFixupDescriptor(0x205, true, "S:data"),
			new OmfFixupDescriptor(0x215, true, "S:data"),
			new OmfFixupDescriptor(0x221, true, "S:data"),
			new OmfFixupDescriptor(0x226, true, "S:data"),
			new OmfFixupDescriptor(0x238, true, "E:__streams"),
			new OmfFixupDescriptor(0x244, true, "S:data"),
			new OmfFixupDescriptor(0x24a, true, "S:data"),
			new OmfFixupDescriptor(0x25a, true, "E:__streams"),
			new OmfFixupDescriptor(0x267, true, "E:__streams"),
			new OmfFixupDescriptor(0x271, true, "S:data"),
			new OmfFixupDescriptor(0x277, true, "S:data"),
			new OmfFixupDescriptor(0x288, false, "E:__fputc"));

		// .data relocations.
		assertOmfFixups(actual_data_fixups,
			new OmfFixupDescriptor(0x004, true, "E:_openbsd_isgraph"),
			new OmfFixupDescriptor(0x00c, true, "E:_openbsd_isprint"),
			new OmfFixupDescriptor(0x014, true, "E:_openbsd_iscntrl"),
			new OmfFixupDescriptor(0x01c, true, "E:_openbsd_isspace"),
			new OmfFixupDescriptor(0x024, true, "E:_openbsd_ispunct"),
			new OmfFixupDescriptor(0x02c, true, "E:_openbsd_isalnum"),
			new OmfFixupDescriptor(0x034, true, "E:_openbsd_isalpha"),
			new OmfFixupDescriptor(0x03c, true, "E:_openbsd_isdigit"),
			new OmfFixupDescriptor(0x044, true, "E:_openbsd_isupper"),
			new OmfFixupDescriptor(0x04c, true, "E:_openbsd_islower"));

		// SEGDEF attributes.
		assertSegdefIsDwordPublicUse32(actual, ".text");
		assertSegdefIsDwordPublicUse32(actual, ".data");
	}

	@Test
	public void test_openbsd_ctype_obj() throws Exception {
		// Expected file.
		OmfFile expected = new OmfFile.Parser(new FileInputStream(openbsd_ctype_file)).parse();
		findSegmentByName(expected, "_TEXT");
		findSegmentByName(expected, "_DATA");
		var expected_text = segmentDataByName(expected, "_TEXT");
		var expected_data = segmentDataByName(expected, "_DATA");

		// Actual file.
		AddressSetView set = findProgramModule("Object Files", "openbsd_ctype.obj");
		File exportedFile = exportObjectFile(set, new OmfRelocatableObjectExporter(), null);
		OmfFile actual = new OmfFile.Parser(new FileInputStream(exportedFile)).parse();
		findSegmentByName(actual, ".text");
		findSegmentByName(actual, ".data");
		var actual_text = segmentDataByName(actual, ".text");
		var actual_data = segmentDataByName(actual, ".data");
		var actual_text_fixups = omfFixupSpecs(actual, ".text");
		var actual_data_fixups = omfFixupSpecs(actual, ".data");

		// Defined symbols.
		assertPublicSymbol(actual, ".text", "_openbsd_isalnum", 0x0000);
		assertPublicSymbol(actual, ".text", "_openbsd_isalpha", 0x001e);
		assertPublicSymbol(actual, ".text", "_openbsd_iscntrl", 0x003c);
		assertPublicSymbol(actual, ".text", "_openbsd_isdigit", 0x005a);
		assertPublicSymbol(actual, ".text", "_openbsd_isgraph", 0x0078);
		assertPublicSymbol(actual, ".text", "_openbsd_islower", 0x0096);
		assertPublicSymbol(actual, ".text", "_openbsd_isprint", 0x00b4);
		assertPublicSymbol(actual, ".text", "_openbsd_ispunct", 0x00d4);
		assertPublicSymbol(actual, ".text", "_openbsd_isspace", 0x00f2);
		assertPublicSymbol(actual, ".text", "_openbsd_isupper", 0x0110);
		assertPublicSymbol(actual, ".text", "_openbsd_isxdigit", 0x012e);
		assertPublicSymbol(actual, ".data", "__openbsd_ctype_", 0x0000);

		// Undefined/external symbols.
		assertTrue(externalSymbolNames(actual).isEmpty());

		// Segment bytes.
		assertSegmentBytes(expected_text, actual_text);
		assertSegmentBytes(expected_data, actual_data);

		// .text relocations.
		assertOmfFixups(actual_text_fixups,
			new OmfFixupDescriptor(0x015, true, "S:data"),
			new OmfFixupDescriptor(0x033, true, "S:data"),
			new OmfFixupDescriptor(0x051, true, "S:data"),
			new OmfFixupDescriptor(0x06f, true, "S:data"),
			new OmfFixupDescriptor(0x08d, true, "S:data"),
			new OmfFixupDescriptor(0x0ab, true, "S:data"),
			new OmfFixupDescriptor(0x0c9, true, "S:data"),
			new OmfFixupDescriptor(0x0e9, true, "S:data"),
			new OmfFixupDescriptor(0x107, true, "S:data"),
			new OmfFixupDescriptor(0x125, true, "S:data"),
			new OmfFixupDescriptor(0x143, true, "S:data"));

		// .data relocations.
		assertOmfFixups(actual_data_fixups);

		// SEGDEF attributes.
		assertSegdefIsDwordPublicUse32(actual, ".text");
		assertSegdefIsDwordPublicUse32(actual, ".data");
	}
}
