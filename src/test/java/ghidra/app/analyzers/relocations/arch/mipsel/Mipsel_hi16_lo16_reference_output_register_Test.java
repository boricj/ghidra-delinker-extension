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

import static ghidra.program.model.relocobj.RelocationGroupAssertions.assertGroups;
import static ghidra.program.model.relocobj.RelocationGroupAssertions.entry;
import static ghidra.program.model.relocobj.RelocationGroupAssertions.gang;
import static ghidra.program.model.relocobj.RelocationGroupAssertions.group;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.Test;

import ghidra.DelinkerIntegrationTest;
import ghidra.app.analyzers.RelocationTableSynthesizerAnalyzer;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.relocobj.RelocationExpressionKind;
import ghidra.program.model.relocobj.RelocationGroupAssertions.ExpectedGroup;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.program.model.relocobj.RelocationGangRoleDescriptor;
import ghidra.util.task.TaskMonitor;

public class Mipsel_hi16_lo16_reference_output_register_Test extends DelinkerIntegrationTest {
	private static final List<String> MEMORY_BLOCK_NAMES = List.of(".text");

	private static final Map<String, Integer> TARGET_SYMBOLS = Map.ofEntries(
		Map.entry("HELLO_WORLD", 0x10020),
		Map.entry("PTR", 0x10030));

	private static final List<ExpectedGroup> EXPECTED_GROUPS = List.of(
		group(RelocationExpressionKind.ABSOLUTE, TARGET_SYMBOLS.get("HELLO_WORLD"), 0,
			gang(RelocationGangRoleDescriptor.HIGH_PAIR, 4, 0xffff, entry(0x00010000, 0)),
			gang(RelocationGangRoleDescriptor.LOW_PAIR, 4, 0xffff, entry(0x00010004, 0))),
		group(RelocationExpressionKind.ABSOLUTE, TARGET_SYMBOLS.get("PTR"), 0,
			gang(RelocationGangRoleDescriptor.HIGH_PAIR, 4, 0xffff, entry(0x00010008, 0)),
			gang(RelocationGangRoleDescriptor.LOW_PAIR, 4, 0xffff, entry(0x0001000c, 0))));

	@Override
	protected String getProgramName() {
		return "src/test/resources/arch/mipsel/reference/hi16_lo16_reference_output_register.gzf";
	}

	@Test
	public void testRelocationTableSynthesizerAnalyzer() throws Exception {
		Program program = getProgram();
		MessageLog log = new MessageLog();
		RelocationTableSynthesizerAnalyzer analyzer = new RelocationTableSynthesizerAnalyzer();
		AddressSetView set = getAddressSetOfMemoryBlocks(program, MEMORY_BLOCK_NAMES);

		assertTrue(analyzer.added(program, set, TaskMonitor.DUMMY, log));

		RelocationTable relocationTable = RelocationTable.get(program);
		assertGroups(relocationTable, set, EXPECTED_GROUPS);
	}
}
