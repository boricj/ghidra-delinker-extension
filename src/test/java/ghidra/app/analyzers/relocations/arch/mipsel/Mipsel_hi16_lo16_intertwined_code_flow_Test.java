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
package ghidra.app.analyzers.relocations.arch.mipsel;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import ghidra.DelinkerIntegrationTest;
import ghidra.app.analyzers.RelocationTableSynthesizerAnalyzer;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.relocobj.ExpectRelocationHighPair;
import ghidra.program.model.relocobj.ExpectRelocationLowPair;
import ghidra.program.model.relocobj.ExpectRelocationRelativePC;
import ghidra.program.model.relocobj.Relocation;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.util.task.TaskMonitor;

public class Mipsel_hi16_lo16_intertwined_code_flow_Test extends DelinkerIntegrationTest {
	private static final List<String> MEMORY_BLOCK_NAMES = List.of(".text");

	private static final List<Relocation> EXPECTED_RELOCATIONS = List.of(
		// .rel.text
		new ExpectRelocationRelativePC(0x00010000, 2, "LAB_00010014", -1),
		// 00000004  00000205 R_MIPS_HI16       00000000   .data
		new ExpectRelocationHighPair(0x00010004, 4, 0xffff, "HELLO_WORLD"),
		// 00000008  00000205 R_MIPS_HI16       00000000   .data
		new ExpectRelocationHighPair(0x00010008, 4, 0xffff, "GOODBYE_WORLD"),
		new ExpectRelocationRelativePC(0x0001000c, 2, "LAB_00010018", -1),
		// 00000010  00000206 R_MIPS_LO16       00000000   .data
		new ExpectRelocationLowPair(0x00010010, 4, 0xffff, "GOODBYE_WORLD", 0),
		// 00000014  00000206 R_MIPS_LO16       00000000   .data
		new ExpectRelocationLowPair(0x00010014, 4, 0xffff, "HELLO_WORLD", 0));

	@Override
	protected String getProgramName() {
		return "src/test/resources/arch/mipsel/reference/hi16_lo16_intertwined_code_flow.gzf";
	}

	@Test
	public void testRelocationTableSynthesizerAnalyzer() throws Exception {
		Program program = getProgram();
		MessageLog log = new MessageLog();
		RelocationTableSynthesizerAnalyzer analyzer = new RelocationTableSynthesizerAnalyzer();
		AddressSetView set = getAddressSetOfMemoryBlocks(program, MEMORY_BLOCK_NAMES);

		assertTrue(analyzer.added(program, set, TaskMonitor.DUMMY, log));

		RelocationTable relocationTable = RelocationTable.get(program);
		List<Relocation> actualRelocations = new ArrayList<>();
		relocationTable.getRelocations(set).forEachRemaining(actualRelocations::add);

		assertArrayEquals(EXPECTED_RELOCATIONS.toArray(), actualRelocations.toArray());
	}
}
