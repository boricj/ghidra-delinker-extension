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
package ghidra.app.util.exporter.asciitable.elf_linux_freestanding;

import java.io.File;

import org.junit.Test;

import ghidra.DelinkerIntegrationTest;
import ghidra.app.util.exporter.ElfRelocatableObjectExporter;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;

public class I386_ctype_o_IntegrationTest extends DelinkerIntegrationTest {
	private static final File ctypeFile =
		new File("src/test/resources/ascii-table/reference/elf_linux_freestanding/i386/ctype.o");

	@Override
	protected String getProgramName() {
		return "src/test/resources/ascii-table/reference/elf_linux_freestanding/i386/ascii-table.elf.gzf";
	}

	@Test
	public void testExport_ctype_o() throws Exception {
		AddressFactory af = getProgram().getAddressFactory();
		AddressSetView set = af.getAddressSet(af.getAddress("0804924e"), af.getAddress("0804938e"))	// .text
				.union(af.getAddressSet(af.getAddress("0804a060"), af.getAddress("0804a160"))); 	// .rodata
		File exportedFile = exportObjectFile(set, new ElfRelocatableObjectExporter(), null);

		ObjectFile ctypeObjectFile = new ElfObjectFile(ctypeFile);
		ObjectFile exportedObjectFile = new ElfObjectFile(exportedFile);

		ctypeObjectFile.compareSectionBytes(".text", exportedObjectFile, ".text");
		ctypeObjectFile.compareSectionSizes(".rel.text", exportedObjectFile, ".rel.text");
		ctypeObjectFile.compareSectionBytes(".rodata", exportedObjectFile, ".rodata");
	}
}
