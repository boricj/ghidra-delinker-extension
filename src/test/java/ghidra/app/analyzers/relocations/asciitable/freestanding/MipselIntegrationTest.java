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
package ghidra.app.analyzers.relocations.asciitable.freestanding;

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
import ghidra.program.model.relocobj.ExpectRelocationAbsolute;
import ghidra.program.model.relocobj.ExpectRelocationHighPair;
import ghidra.program.model.relocobj.ExpectRelocationLowPair;
import ghidra.program.model.relocobj.ExpectRelocationMIPS26;
import ghidra.program.model.relocobj.ExpectRelocationRelativeSymbol;
import ghidra.program.model.relocobj.Relocation;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.util.task.TaskMonitor;

public class MipselIntegrationTest extends DelinkerIntegrationTest {
	private static final List<String> MEMORY_BLOCK_NAMES = List.of(
		".sbss",
		".sdata",
		".rodata",
		".text");

	private static final List<Relocation> EXPECTED_RELOCATIONS = List.of(
		// .rel.text
		// 00400208  00002605 R_MIPS_HI16            00000000   errno
		new ExpectRelocationHighPair(0x00400208, 4, 0xffff, "errno"),
		// 00400210  00002606 R_MIPS_LO16            00000000   errno
		new ExpectRelocationLowPair(0x00400210, 4, 0xffff, "errno", 0),
		// 00400220  00002705 R_MIPS_HI16            00000000   _gp
		new ExpectRelocationHighPair(0x00400220, 4, 0xffff, "_gp"),
		// 00400224  00002706 R_MIPS_LO16            00000000   _gp
		new ExpectRelocationLowPair(0x00400224, 4, 0xffff, "_gp", 0),
		// 0040023c  00003105 R_MIPS_HI16            00000008   environ
		new ExpectRelocationHighPair(0x0040023c, 4, 0xffff, "environ"),
		// 00400240  00003106 R_MIPS_LO16            00000008   environ
		new ExpectRelocationLowPair(0x00400240, 4, 0xffff, "environ", 0),
		// 00400258  00002a05 R_MIPS_HI16            00000004   _auxv
		new ExpectRelocationHighPair(0x00400258, 4, 0xffff, "_auxv"),
		// 0040025c  00002a06 R_MIPS_LO16            00000004   _auxv
		new ExpectRelocationLowPair(0x0040025c, 4, 0xffff, "_auxv", 0),
		// 00400270  00003704 R_MIPS_26              000003e4   main
		new ExpectRelocationMIPS26(0x00400270, "main", 0),
		// 0040028c  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x0040028c, 4, 0xffff, "sys_write"),
		// 00400290  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x00400290, 4, 0xffff, "sys_write", 0),
		// 004002b8  00002605 R_MIPS_HI16            00000000   errno
		new ExpectRelocationHighPair(0x004002b8, 4, 0xffff, "errno"),
		// 004002bc  00002606 R_MIPS_LO16            00000000   errno
		new ExpectRelocationLowPair(0x004002bc, 4, 0xffff, "errno", 0),
		// 004002dc  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x004002dc, 4, 0xffff, "fileno"),
		// 004002e0  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x004002e0, 4, 0xffff, "fileno", 0),
		// 004002f8  00003005 R_MIPS_HI16            00000134   write
		new ExpectRelocationHighPair(0x004002f8, 4, 0xffff, "write"),
		// 004002fc  00003006 R_MIPS_LO16            00000134   write
		new ExpectRelocationLowPair(0x004002fc, 4, 0xffff, "write", 0),
		// 0040033c  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x0040033c, 4, 0xffff, "fputc"),
		// 00400340  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x00400340, 4, 0xffff, "fputc", 0),
		// 00400380  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x00400380, 4, 0xffff, "putchar"),
		// 00400384  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x00400384, 4, 0xffff, "putchar", 0),
		// 004003c8  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x004003c8, 4, 0xffff, "putchar"),
		// 004003cc  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x004003cc, 4, 0xffff, "putchar", 0),
		// 00400420  00003305 R_MIPS_HI16            0000020c   print_number
		new ExpectRelocationHighPair(0x00400420, 4, 0xffff, "print_number"),
		// 00400424  00003306 R_MIPS_LO16            0000020c   print_number
		new ExpectRelocationLowPair(0x00400424, 4, 0xffff, "print_number", 0),

		// 00400434  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x00400434, 4, 0xffff, "putchar"),
		// 00400438  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x00400438, 4, 0xffff, "putchar", 0),
		// 00400448  00003805 R_MIPS_HI16            00000590   isgraph
		new ExpectRelocationHighPair(0x00400448, 4, 0xffff, "isgraph"),
		// 0040044c  00003806 R_MIPS_LO16            00000590   isgraph
		new ExpectRelocationLowPair(0x0040044c, 4, 0xffff, "isgraph", 0),
		// 00400464  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x00400464, 4, 0xffff, "putchar"),
		// 00400468  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x00400468, 4, 0xffff, "putchar", 0),
		// 00400478  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x00400478, 4, 0xffff, "putchar"),
		// 0040047c  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x0040047c, 4, 0xffff, "putchar", 0),
		// 00400498  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x00400498, 4, 0xffff, "putchar"),
		// 0040049c  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x0040049c, 4, 0xffff, "putchar", 0),
		// 004004b4  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x004004b4, 4, 0xffff, "putchar"),
		// 004004b8  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x004004b8, 4, 0xffff, "putchar", 0),
		// 004004f8  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x004004f8, 4, 0xffff, "putchar"),
		// 004004fc  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x004004fc, 4, 0xffff, "putchar", 0),
		// 00400550  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x00400550, 4, 0xffff, "putchar"),
		// 00400554  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x00400554, 4, 0xffff, "putchar", 0),
		// 00400570  00003c07 R_MIPS_GPREL16         00000000   COLUMNS
		new ExpectRelocationRelativeSymbol(0x00400570, 2, 0xffff, 0, "COLUMNS", 0, "_gp"),
		// 00400598  00002405 R_MIPS_HI16            00000000   s_ascii_properties
		new ExpectRelocationHighPair(0x00400598, 4, 0xffff, "s_ascii_properties"),
		// 0040059c  00002406 R_MIPS_LO16            00000000   s_ascii_properties
		new ExpectRelocationLowPair(0x0040059c, 4, 0xffff, "s_ascii_properties", 0),
		// 004005a8  00003b05 R_MIPS_HI16            000002a8   print_ascii_entry
		new ExpectRelocationHighPair(0x004005a8, 4, 0xffff, "print_ascii_entry"),
		// 004005ac  00003b06 R_MIPS_LO16            000002a8   print_ascii_entry
		new ExpectRelocationLowPair(0x004005ac, 4, 0xffff, "print_ascii_entry", 0),
		// 004005b8  00003c07 R_MIPS_GPREL16         00000000   COLUMNS
		new ExpectRelocationRelativeSymbol(0x004005b8, 2, 0xffff, 0, "COLUMNS", 0, "_gp"),
		// 00400610  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x00400610, 4, 0xffff, "_ctype_"),
		// 00400614  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x00400614, 4, 0xffff, "_ctype_", 1),
		// 00400648  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x00400648, 4, 0xffff, "_ctype_"),
		// 0040064c  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x0040064c, 4, 0xffff, "_ctype_", 1),
		// 00400680  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x00400680, 4, 0xffff, "_ctype_"),
		// 00400684  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x00400684, 4, 0xffff, "_ctype_", 1),
		// 004006b8  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x004006b8, 4, 0xffff, "_ctype_"),
		// 004006bc  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x004006bc, 4, 0xffff, "_ctype_", 1),
		// 004006f0  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x004006f0, 4, 0xffff, "_ctype_"),
		// 004006f4  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x004006f4, 4, 0xffff, "_ctype_", 1),
		// 00400728  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x00400728, 4, 0xffff, "_ctype_"),
		// 0040072c  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x0040072c, 4, 0xffff, "_ctype_", 1),
		// 00400760  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x00400760, 4, 0xffff, "_ctype_"),
		// 00400764  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x00400764, 4, 0xffff, "_ctype_", 1),
		// 00400798  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x00400798, 4, 0xffff, "_ctype_"),
		// 0040079c  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x0040079c, 4, 0xffff, "_ctype_", 1),
		// 004007d0  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x004007d0, 4, 0xffff, "_ctype_"),
		// 004007d4  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x004007d4, 4, 0xffff, "_ctype_", 1),
		// 00400808  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x00400808, 4, 0xffff, "_ctype_"),
		// 0040080c  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x0040080c, 4, 0xffff, "_ctype_", 1),
		// 00400840  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x00400840, 4, 0xffff, "_ctype_"),
		// 00400844  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x00400844, 4, 0xffff, "_ctype_", 1),

		// .rel.text.nolibc_raise
		// 00400880  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x00400880, 4, 0xffff, "sys_getpid"),
		// 00400884  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x00400884, 4, 0xffff, "sys_getpid", 0),
		// 00400898  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x00400898, 4, 0xffff, "sys_kill"),
		// 0040089c  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x0040089c, 4, 0xffff, "sys_kill", 0),

		// .rel.text.nolibc_memcpy
		// 0040091c  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x0040091c, 4, 0xffff, "_nolibc_memcpy_up"),
		// 00400920  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x00400920, 4, 0xffff, "_nolibc_memcpy_up", 0),

		// .rel.text.nolibc_abort
		// 00400974  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x00400974, 4, 0xffff, "sys_getpid"),
		// 00400978  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x00400978, 4, 0xffff, "sys_getpid", 0),
		// 0040098c  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x0040098c, 4, 0xffff, "sys_kill"),
		// 00400990  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x00400990, 4, 0xffff, "sys_kill", 0),

		// .rel.rodata
		// 004009b0  00003802 R_MIPS_32              00000590   isgraph
		new ExpectRelocationAbsolute(0x004009b0, 4, "isgraph", 0),
		// 004009b8  00003a02 R_MIPS_32              00000600   isprint
		new ExpectRelocationAbsolute(0x004009b8, 4, "isprint", 0),
		// 004009c0  00003e02 R_MIPS_32              00000520   iscntrl
		new ExpectRelocationAbsolute(0x004009c0, 4, "iscntrl", 0),
		// 004009c8  00002d02 R_MIPS_32              00000670   isspace
		new ExpectRelocationAbsolute(0x004009c8, 4, "isspace", 0),
		// 004009d0  00002c02 R_MIPS_32              00000638   ispunct
		new ExpectRelocationAbsolute(0x004009d0, 4, "ispunct", 0),
		// 004009d8  00003902 R_MIPS_32              000004b0   isalnum
		new ExpectRelocationAbsolute(0x004009d8, 4, "isalnum", 0),
		// 004009e0  00003502 R_MIPS_32              000004e8   isalpha
		new ExpectRelocationAbsolute(0x004009e0, 4, "isalpha", 0),
		// 004009e8  00003d02 R_MIPS_32              00000558   isdigit
		new ExpectRelocationAbsolute(0x004009e8, 4, "isdigit", 0),
		// 004009f0  00003402 R_MIPS_32              000006a8   isupper
		new ExpectRelocationAbsolute(0x004009f0, 4, "isupper", 0),
		// 004009f8  00002b02 R_MIPS_32              000005c8   islower
		new ExpectRelocationAbsolute(0x004009f8, 4, "islower", 0));

	@Override
	protected String getProgramName() {
		return "src/test/resources/ascii-table/reference/freestanding/mipsel/ascii-table.elf.gzf";
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
