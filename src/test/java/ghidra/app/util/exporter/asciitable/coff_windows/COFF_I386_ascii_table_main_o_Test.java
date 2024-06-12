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
package ghidra.app.util.exporter.asciitable.coff_windows;

import java.io.File;

import org.junit.Test;

import ghidra.DelinkerIntegrationTest;
import ghidra.app.util.exporter.CoffRelocatableObjectExporter;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;

public class COFF_I386_ascii_table_main_o_Test extends DelinkerIntegrationTest {
	private static final File mainFile =
		new File("src/test/resources/ascii-table/reference/coff_windows/i386/main.obj");

	@Override
	protected String getProgramName() {
		return "src/test/resources/ascii-table/reference/coff_windows/i386/ascii-table.exe.gzf";
	}

	@Test
	public void testExport_main_o() throws Exception {
		AddressFactory af = getProgram().getAddressFactory();
		AddressSetView set = af.getAddressSet(af.getAddress("00407310"), af.getAddress("004074d3"))	// .text
				.union(af.getAddressSet(af.getAddress("00475000"), af.getAddress("00475003")))	 	// .data
				.union(af.getAddressSet(af.getAddress("00469e50"), af.getAddress("00469ea7"))); 	// .rdata
		File exportedFile = exportObjectFile(set, new CoffRelocatableObjectExporter(), null);

		ObjectFile mainObjectFile = new CoffObjectFile(getProgram(), mainFile);
		ObjectFile exportedObjectFile = new CoffObjectFile(getProgram(), exportedFile);

		mainObjectFile.compareSectionBytes(".text$mn", exportedObjectFile, ".text");
		mainObjectFile.compareSectionBytes(".data", exportedObjectFile, ".data");
		mainObjectFile.compareSectionBytes(".rdata", exportedObjectFile, ".rdata");
	}
}
