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
package ghidra.app.util.exporter.asciitable.freestanding;

import java.io.File;
import java.util.Map;

import org.junit.Test;

import ghidra.DelinkerIntegrationTest;
import ghidra.app.util.exporter.ElfRelocatableObjectExporter;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;

public class Mipsel_main_o_IntegrationTest extends DelinkerIntegrationTest {
	private static final File mainFile =
		new File("src/test/resources/ascii-table/reference/freestanding/mipsel/main.o");

	@Override
	protected String getProgramName() {
		return "src/test/resources/ascii-table/reference/freestanding/mipsel/ascii-table.elf.gzf";
	}

	@Test
	public void testExport_main_o() throws Exception {
		AddressFactory af = getProgram().getAddressFactory();
		AddressSetView set = af.getAddressSet(af.getAddress("00400150"), af.getAddress("004005ff"))	// .text
				//.union(af.getAddressSet(af.getAddress("00400870"), af.getAddress("004008bb")))      // .text.nolibc_raise
				//.union(af.getAddressSet(af.getAddress("004008bc"), af.getAddress("00400913")))      // .text.nolibc_memove
				//.union(af.getAddressSet(af.getAddress("00400914"), af.getAddress("0040093b")))      // .text.nolibc_memcpy
				//.union(af.getAddressSet(af.getAddress("0040093c"), af.getAddress("0040096b")))      // .text.nolibc_memset
				//.union(af.getAddressSet(af.getAddress("0040096c"), af.getAddress("004009a3")))      // .text.nolibc_abort
				.union(af.getAddressSet(af.getAddress("00410b10"), af.getAddress("00410b17")))      // .sdata
				.union(af.getAddressSet(af.getAddress("004009b0"), af.getAddress("004009ff")))      // .rodata
				.union(af.getAddressSet(af.getAddress("00410b18"), af.getAddress("00410b23")));     // .sbss
		File exportedFile = exportObjectFile(set, new ElfRelocatableObjectExporter(), null);

		Map<Integer, byte[]> text_patches = Map.ofEntries(
			Map.entry(0x140, new byte[2]),
			Map.entry(0x190, new byte[2]),
			Map.entry(0x1f0, new byte[2]),
			Map.entry(0x234, new byte[2]),
			Map.entry(0x27c, new byte[2]),
			Map.entry(0x2e8, new byte[2]),
			Map.entry(0x318, new byte[2]),
			Map.entry(0x32c, new byte[2]),
			Map.entry(0x34c, new byte[2]),
			Map.entry(0x368, new byte[2]),
			Map.entry(0x3ac, new byte[2]),
			Map.entry(0x404, new byte[2]));

		ObjectFile mainObjectFile = new ElfObjectFile(mainFile);
		ObjectFile exportedObjectFile = new ElfObjectFile(exportedFile);

		mainObjectFile.compareSectionBytes(".text", exportedObjectFile, ".text", text_patches);
		mainObjectFile.compareSectionSizes(".rel.text", exportedObjectFile, ".rel.text");
		mainObjectFile.compareSectionBytes(".sdata", exportedObjectFile, ".sdata");
		mainObjectFile.compareSectionBytes(".rodata", exportedObjectFile, ".rodata");
		mainObjectFile.compareSectionSizes(".rel.rodata", exportedObjectFile, ".rel.rodata");
		mainObjectFile.compareSectionBytes(".sbss", exportedObjectFile, ".sbss");
	}
}
