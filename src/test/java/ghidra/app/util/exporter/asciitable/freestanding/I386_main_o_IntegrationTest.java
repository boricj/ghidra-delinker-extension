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

public class I386_main_o_IntegrationTest extends DelinkerIntegrationTest {
	private static final File mainFile =
		new File("src/test/resources/ascii-table/reference/freestanding/i386/main.o");

	@Override
	protected String getProgramName() {
		return "src/test/resources/ascii-table/reference/freestanding/i386/ascii-table.elf.gzf";
	}

	@Test
	public void testExport_main_o() throws Exception {
		AddressFactory af = getProgram().getAddressFactory();
		AddressSetView set = af.getAddressSet(af.getAddress("08049000"), af.getAddress("0804924d"))	// .text
				.union(af.getAddressSet(af.getAddress("0804b000"), af.getAddress("0804b003")))	 	// .data
				.union(af.getAddressSet(af.getAddress("0804a000"), af.getAddress("0804a053"))); 	// .rodata
		File exportedFile = exportObjectFile(set, new ElfRelocatableObjectExporter(), null);

		Map<Integer, byte[]> text_patches = Map.ofEntries(
			Map.entry(0x8a, new byte[] { 0x3e, 0x01, 0x00, 0x00 }),
			Map.entry(0xd5, new byte[] { -65, -1, -1, -1 }),
			Map.entry(0x151, new byte[] { -90, -1, -1, -1 }),
			Map.entry(0x163, new byte[] { 0x67, -24, -4, -1, -1, -1 }),
			Map.entry(0x21e, new byte[] { 0x1d, -1, -1, -1 }));

		ObjectFile mainObjectFile = new ElfObjectFile(mainFile);
		ObjectFile exportedObjectFile = new ElfObjectFile(exportedFile);

		mainObjectFile.compareSectionBytes(".text", exportedObjectFile, ".text", text_patches);
		mainObjectFile.compareSectionBytes(".rodata", exportedObjectFile, ".rodata");
		mainObjectFile.compareSectionSizes(".rel.rodata", exportedObjectFile, ".rel.rodata");
	}
}
