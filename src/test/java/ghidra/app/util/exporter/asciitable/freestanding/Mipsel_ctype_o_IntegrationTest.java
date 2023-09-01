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

import org.junit.Test;

import ghidra.DelinkerIntegrationTest;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;

public class Mipsel_ctype_o_IntegrationTest extends DelinkerIntegrationTest {
	private static final String INPUT_FORMAT = "elf32-little";

	private static final File ctypeFile =
		new File("src/test/resources/ascii-table/reference/freestanding/mipsel/ctype.o");

	@Override
	protected String getProgramName() {
		return "src/test/resources/ascii-table/reference/freestanding/mipsel/ascii-table.elf.gzf";
	}

	@Test
	public void testExport_ctype_o() throws Exception {
		AddressFactory af = getProgram().getAddressFactory();
		AddressSetView set = af.getAddressSet(af.getAddress("00400600"), af.getAddress("0040086f"))	// .text
				.union(af.getAddressSet(af.getAddress("00400a00"), af.getAddress("00400b0f"))); 	// .rodata
		File exportedFile = exportElfObjectFile(set, null);

		compareElfSectionBytes(INPUT_FORMAT, ctypeFile, ".text", exportedFile, ".text");
		compareElfSectionSizes(INPUT_FORMAT, ctypeFile, ".rel.text", exportedFile, ".rel.text");
		compareElfSectionBytes(INPUT_FORMAT, ctypeFile, ".rodata", exportedFile, ".rodata");
	}
}
