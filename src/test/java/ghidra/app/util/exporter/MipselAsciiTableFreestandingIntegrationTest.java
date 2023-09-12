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
package ghidra.app.util.exporter;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;

import org.junit.Test;

import ghidra.DelinkerIntegrationTest;
import ghidra.app.analyzers.RelocationTableSynthesizerAnalyzer;
import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class MipselAsciiTableFreestandingIntegrationTest extends DelinkerIntegrationTest {
	private static final String ACTUAL_RAW_FILENAMES_FORMAT =
		"src/test/resources/ascii-table/reference/freestanding/mipsel/ascii-table%s.bin";

	private static final List<String> MEMORY_BLOCK_NAMES = List.of(
		".sbss",
		".sdata",
		".rodata",
		".text");

	@Override
	protected String getProgramName() {
		return "src/test/resources/ascii-table/reference/freestanding/mipsel/ascii-table.elf.gzf";
	}

	@Test
	public void testElfRelocatableObjectExporter() throws Exception {
		Program program = getProgram();
		MessageLog log = new MessageLog();
		RelocationTableSynthesizerAnalyzer analyzer = new RelocationTableSynthesizerAnalyzer();
		AddressSetView set = getAddressSetOfMemoryBlocks(program, MEMORY_BLOCK_NAMES);

		assertTrue(analyzer.added(program, set, TaskMonitor.DUMMY, log));

		Exporter exporter = new ElfRelocatableObjectExporter();
		List<Option> options = exporter.getOptions(new DomainObjectService() {
			@Override
			public DomainObject getDomainObject() {
				return program;
			}

		});
		exporter.setOptions(options);

		File exportedFile = createTempFileForTest(".o");
		assertTrue(exporter.export(exportedFile, program, set, TaskMonitor.DUMMY));

		for (String sectionName : MEMORY_BLOCK_NAMES) {
			compareElfSectionWithRawFile(exportedFile, "elf32-little", ACTUAL_RAW_FILENAMES_FORMAT,
				sectionName);
		}
	}
}
