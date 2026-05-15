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
package ghidra.app.util.exporter.freelist_allocator.omf_windows;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileInputStream;

import org.junit.Test;

import ghidra.DelinkerIntegrationTest;
import ghidra.app.util.exporter.OmfRelocatableObjectExporter;
import ghidra.program.model.address.AddressSetView;
import net.boricj.bft.omf.OmfFile;

public class X86_Test extends DelinkerIntegrationTest {

	private static final File main_file = new File(
		"src/test/resources/programs/freelist-allocator/reference/omf/windows-borland/x86/main.obj");

	private static final File allocator_file = new File(
		"src/test/resources/programs/freelist-allocator/reference/omf/windows-borland/x86/allocator.obj");

	@Override
	protected String getProgramName() {
		return "src/test/resources/programs/freelist-allocator/reference/omf/windows-borland/x86/freelist-allocator.exe.gzf";
	}

	@Test
	public void test_main_obj() throws Exception {
		// Expected file.
		OmfFile expected = new OmfFile.Parser(new FileInputStream(main_file)).parse();
		var expected_text = segmentDataByName(expected, "_TEXT");
		var expected_data = segmentDataByName(expected, "_DATA");
		var expected_bss = segmentDataByName(expected, "_BSS");

		// Actual file.
		AddressSetView set = findProgramModule("Object Files", "main.obj");
		File exportedFile = exportObjectFile(set, new OmfRelocatableObjectExporter(), null);
		OmfFile actual = new OmfFile.Parser(new FileInputStream(exportedFile)).parse();
		var actual_text = segmentDataByName(actual, ".text");
		var actual_data = segmentDataByName(actual, ".data");
		var actual_bss = segmentDataByName(actual, ".bss");
		var actual_text_fixups = omfFixupSpecs(actual, ".text");
		var actual_data_fixups = omfFixupSpecs(actual, ".data");
		var actual_bss_fixups = omfFixupSpecs(actual, ".bss");

		// Defined symbols.
		assertPublicSymbol(actual, ".text", "_main", 0x0042);
		assertPublicSymbol(actual, ".data", "_s_snapshot_1", 0x0000);
		assertPublicSymbol(actual, ".data", "_s_snapshot_2", 0x0180);
		assertPublicSymbol(actual, ".data", "_s_snapshot_3", 0x0300);
		assertPublicSymbol(actual, ".data", "_s_snapshot_4", 0x0480);
		assertPublicSymbol(actual, ".data", "_s_snapshot_5", 0x0600);
		assertPublicSymbol(actual, ".data", "_s_heap_ranges", 0x0780);
		assertPublicSymbol(actual, ".bss", "_s_heap", 0x0000);

		// Undefined/external symbols.
		assertExternalSymbol(actual, "_freelist_alloc");
		assertExternalSymbol(actual, "_memset");
		assertExternalSymbol(actual, "_freelist_init");
		assertExternalSymbol(actual, "_memcmp");
		assertExternalSymbol(actual, "_freelist_free");
		assertExternalSymbol(actual, "_puts");
		assertEquals(6, externalSymbolNames(actual).size());

		// Segment bytes.
		assertSegmentBytes(expected_text, actual_text);
		assertSegmentBytes(expected_data, actual_data);
		assertSegmentBytes(expected_bss, actual_bss);

		// .text relocations.
		assertOmfFixups(actual_text_fixups,
			new OmfFixupDescriptor(0x00f, false, "E:_freelist_alloc"),
			new OmfFixupDescriptor(0x035, false, "E:_memset"),
			new OmfFixupDescriptor(0x04b, true, "S:bss"),
			new OmfFixupDescriptor(0x058, false, "E:_freelist_init"),
			new OmfFixupDescriptor(0x060, true, "S:data"),
			new OmfFixupDescriptor(0x066, true, "S:data"),
			new OmfFixupDescriptor(0x06e, true, "S:data"),
			new OmfFixupDescriptor(0x078, false, "E:_memcmp"),
			new OmfFixupDescriptor(0x0c9, true, "S:data"),
			new OmfFixupDescriptor(0x0ce, true, "S:data"),
			new OmfFixupDescriptor(0x0d6, true, "S:data"),
			new OmfFixupDescriptor(0x0e0, false, "E:_memcmp"),
			new OmfFixupDescriptor(0x10a, false, "E:_freelist_free"),
			new OmfFixupDescriptor(0x11c, true, "S:data"),
			new OmfFixupDescriptor(0x121, true, "S:data"),
			new OmfFixupDescriptor(0x129, true, "S:data"),
			new OmfFixupDescriptor(0x133, false, "E:_memcmp"),
			new OmfFixupDescriptor(0x15d, false, "E:_freelist_free"),
			new OmfFixupDescriptor(0x16f, true, "S:data"),
			new OmfFixupDescriptor(0x174, true, "S:data"),
			new OmfFixupDescriptor(0x17c, true, "S:data"),
			new OmfFixupDescriptor(0x186, false, "E:_memcmp"),
			new OmfFixupDescriptor(0x1ab, false, "E:_freelist_free"),
			new OmfFixupDescriptor(0x1bd, true, "S:data"),
			new OmfFixupDescriptor(0x1c3, true, "S:data"),
			new OmfFixupDescriptor(0x1cb, true, "S:data"),
			new OmfFixupDescriptor(0x1d5, false, "E:_memcmp"),
			new OmfFixupDescriptor(0x1e6, true, "S:data"),
			new OmfFixupDescriptor(0x1eb, false, "E:_puts"));

		// .data relocations.
		assertOmfFixups(actual_data_fixups,
			new OmfFixupDescriptor(0x180, true, "S:bss"),
			new OmfFixupDescriptor(0x1a0, true, "S:bss"),
			new OmfFixupDescriptor(0x1c0, true, "S:bss"),
			new OmfFixupDescriptor(0x1e0, true, "S:bss"),
			new OmfFixupDescriptor(0x200, true, "S:bss"),
			new OmfFixupDescriptor(0x240, true, "S:bss"),
			new OmfFixupDescriptor(0x280, true, "S:bss"),
			new OmfFixupDescriptor(0x300, true, "S:bss"),
			new OmfFixupDescriptor(0x320, true, "S:bss"),
			new OmfFixupDescriptor(0x340, true, "S:bss"),
			new OmfFixupDescriptor(0x360, true, "S:bss"),
			new OmfFixupDescriptor(0x380, true, "S:bss"),
			new OmfFixupDescriptor(0x3c0, true, "S:bss"),
			new OmfFixupDescriptor(0x400, true, "S:bss"),
			new OmfFixupDescriptor(0x480, true, "S:bss"),
			new OmfFixupDescriptor(0x4a0, true, "S:bss"),
			new OmfFixupDescriptor(0x500, true, "S:bss"),
			new OmfFixupDescriptor(0x780, true, "S:data"),
			new OmfFixupDescriptor(0x784, true, "S:data"),
			new OmfFixupDescriptor(0x788, true, "S:data"),
			new OmfFixupDescriptor(0x78c, true, "S:data"),
			new OmfFixupDescriptor(0x790, true, "S:data"),
			new OmfFixupDescriptor(0x794, true, "S:data"),
			new OmfFixupDescriptor(0x798, true, "S:data"),
			new OmfFixupDescriptor(0x79c, true, "S:data"),
			new OmfFixupDescriptor(0x7a0, true, "S:data"),
			new OmfFixupDescriptor(0x7a4, true, "S:data"));

		// .bss relocations.
		assertOmfFixups(actual_bss_fixups);

		// SEGDEF attributes.
		assertSegdefIsDwordPublicUse32(actual, ".text");
		assertSegdefIsDwordPublicUse32(actual, ".data");
		assertSegdefIsDwordPublicUse32(actual, ".bss");
	}

	@Test
	public void test_allocator_obj() throws Exception {
		// Expected file.
		OmfFile expected = new OmfFile.Parser(new FileInputStream(allocator_file)).parse();
		var expected_text = segmentDataByName(expected, "_TEXT");

		// Actual file.
		AddressSetView set = findProgramModule("Object Files", "allocator.obj");
		File exportedFile = exportObjectFile(set, new OmfRelocatableObjectExporter(), null);
		OmfFile actual = new OmfFile.Parser(new FileInputStream(exportedFile)).parse();
		var actual_text = segmentDataByName(actual, ".text");
		var actual_text_fixups = omfFixupSpecs(actual, ".text");

		// Defined symbols.
		assertPublicSymbol(actual, ".text", "_freelist_init", 0x00f5);
		assertPublicSymbol(actual, ".text", "_freelist_alloc", 0x010c);
		assertPublicSymbol(actual, ".text", "_freelist_free", 0x0199);

		// Undefined/external symbols.
		assertExternalSymbol(actual, "_memset");
		assertEquals(1, externalSymbolNames(actual).size());

		// Segment bytes.
		assertSegmentBytes(expected_text, actual_text);

		// .text relocations.
		assertOmfFixups(actual_text_fixups,
			new OmfFixupDescriptor(0x1d6, false, "E:_memset"),
			new OmfFixupDescriptor(0x23e, false, "E:_memset"));

		// SEGDEF attributes.
		assertSegdefIsDwordPublicUse32(actual, ".text");
	}
}
