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
package ghidra.app.analyzers.relocations.asciitable_linux_freestanding;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

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
import ghidra.program.model.relocobj.ExpectRelocationRelativePC;
import ghidra.program.model.relocobj.ExpectRelocationRelativeSymbol;
import ghidra.program.model.relocobj.Relocation;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.util.task.TaskMonitor;

public class Mipsel_ascii_table_Test extends DelinkerIntegrationTest {
	private static final List<String> MEMORY_BLOCK_NAMES = List.of(
		".sbss",
		".sdata",
		".rodata",
		".text");

	private static final Map<String, Integer> TARGET_SYMBOLS = Map.ofEntries(
		Map.entry("sys_getpid", 0x400150),
		Map.entry("LAB_0040016c", 0x40016c),
		Map.entry("sys_kill", 0x400174),
		Map.entry("LAB_00400190", 0x400190),
		Map.entry("sys_write", 0x400198),
		Map.entry("LAB_004001b4", 0x4001b4),
		Map.entry("_nolibc_memcpy_up", 0x4001bc),
		Map.entry("LAB_004001cc", 0x4001cc),
		Map.entry("LAB_004001e0", 0x4001e0),
		Map.entry("fileno", 0x4001f4),
		Map.entry("LAB_00400208", 0x400208),
		Map.entry("LAB_0040024c", 0x40024c),
		Map.entry("write", 0x400284),
		Map.entry("LAB_004002a4", 0x4002a4),
		Map.entry("LAB_004002b4", 0x4002b4),
		Map.entry("fputc", 0x4002cc),
		Map.entry("LAB_00400314", 0x400314),
		Map.entry("LAB_00400324", 0x400324),
		Map.entry("putchar", 0x400330),
		Map.entry("print_number", 0x40035c),
		Map.entry("LAB_0040037c", 0x40037c),
		Map.entry("LAB_00400390", 0x400390),
		Map.entry("LAB_00400394", 0x400394),
		Map.entry("LAB_004003e0", 0x4003e0),
		Map.entry("print_ascii_entry", 0x4003f8),
		Map.entry("LAB_00400474", 0x400474),
		Map.entry("LAB_00400494", 0x400494),
		Map.entry("LAB_004004b0", 0x4004b0),
		Map.entry("LAB_004004c4", 0x4004c4),
		Map.entry("LAB_004004c8", 0x4004c8),
		Map.entry("LAB_00400510", 0x400510),
		Map.entry("main", 0x400534),
		Map.entry("LAB_0040054c", 0x40054c),
		Map.entry("LAB_00400550", 0x400550),
		Map.entry("LAB_00400564", 0x400564),
		Map.entry("LAB_004005dc", 0x4005dc),
		Map.entry("isalnum", 0x400600),
		Map.entry("LAB_0040062c", 0x40062c),
		Map.entry("isalpha", 0x400638),
		Map.entry("LAB_00400664", 0x400664),
		Map.entry("iscntrl", 0x400670),
		Map.entry("LAB_0040069c", 0x40069c),
		Map.entry("isdigit", 0x4006a8),
		Map.entry("LAB_004006d4", 0x4006d4),
		Map.entry("isgraph", 0x4006e0),
		Map.entry("LAB_0040070c", 0x40070c),
		Map.entry("islower", 0x400718),
		Map.entry("LAB_00400744", 0x400744),
		Map.entry("isprint", 0x400750),
		Map.entry("LAB_0040077c", 0x40077c),
		Map.entry("ispunct", 0x400788),
		Map.entry("LAB_004007b4", 0x4007b4),
		Map.entry("isspace", 0x4007c0),
		Map.entry("LAB_004007ec", 0x4007ec),
		Map.entry("isupper", 0x4007f8),
		Map.entry("LAB_00400824", 0x400824),
		Map.entry("LAB_0040085c", 0x40085c),
		Map.entry("LAB_004008dc", 0x4008dc),
		Map.entry("LAB_004008f4", 0x4008f4),
		Map.entry("LAB_00400904", 0x400904),
		Map.entry("LAB_0040094c", 0x40094c),
		Map.entry("LAB_00400958", 0x400958),
		Map.entry("LAB_0040099c", 0x40099c),
		Map.entry("s_ascii_properties", 0x4009b0),
		Map.entry("_ctype_", 0x400a00),
		Map.entry("COLUMNS", 0x410b10),
		Map.entry("errno", 0x410b18),
		Map.entry("_auxv", 0x410b1c),
		Map.entry("environ", 0x410b20),
		Map.entry("_gp", 0x418b00));

	private static final List<Relocation> EXPECTED_RELOCATIONS = List.of(
		// .rel.text
		new ExpectRelocationRelativePC(0x00400160, 4, 0xffff, TARGET_SYMBOLS.get("LAB_0040016c"),
			-4),
		new ExpectRelocationRelativePC(0x00400184, 4, 0xffff, TARGET_SYMBOLS.get("LAB_00400190"),
			-4),
		new ExpectRelocationRelativePC(0x004001a8, 4, 0xffff, TARGET_SYMBOLS.get("LAB_004001b4"),
			-4),
		new ExpectRelocationRelativePC(0x004001c4, 4, 0xffff, TARGET_SYMBOLS.get("LAB_004001e0"),
			-4),
		new ExpectRelocationRelativePC(0x004001e4, 4, 0xffff, TARGET_SYMBOLS.get("LAB_004001cc"),
			-4),
		new ExpectRelocationRelativePC(0x004001f4, 4, 0xffff, TARGET_SYMBOLS.get("LAB_00400208"),
			-4),
		// 00400208  00002605 R_MIPS_HI16            00000000   errno
		new ExpectRelocationHighPair(0x00400208, 4, 0xffff, TARGET_SYMBOLS.get("errno")),
		// 00400210  00002606 R_MIPS_LO16            00000000   errno
		new ExpectRelocationLowPair(0x00400210, 4, 0xffff, TARGET_SYMBOLS.get("errno"), 0),
		// 00400220  00002705 R_MIPS_HI16            00000000   _gp
		new ExpectRelocationHighPair(0x00400220, 4, 0xffff, TARGET_SYMBOLS.get("_gp")),
		// 00400224  00002706 R_MIPS_LO16            00000000   _gp
		new ExpectRelocationLowPair(0x00400224, 4, 0xffff, TARGET_SYMBOLS.get("_gp"), 0),
		// 0040023c  00003105 R_MIPS_HI16            00000008   environ
		new ExpectRelocationHighPair(0x0040023c, 4, 0xffff, TARGET_SYMBOLS.get("environ")),
		// 00400240  00003106 R_MIPS_LO16            00000008   environ
		new ExpectRelocationLowPair(0x00400240, 4, 0xffff, TARGET_SYMBOLS.get("environ"), 0),
		new ExpectRelocationRelativePC(0x00400250, 4, 0xffff, TARGET_SYMBOLS.get("LAB_0040024c"),
			-4),
		// 00400258  00002a05 R_MIPS_HI16            00000004   _auxv
		new ExpectRelocationHighPair(0x00400258, 4, 0xffff, TARGET_SYMBOLS.get("_auxv")),
		// 0040025c  00002a06 R_MIPS_LO16            00000004   _auxv
		new ExpectRelocationLowPair(0x0040025c, 4, 0xffff, TARGET_SYMBOLS.get("_auxv"), 0),
		// 00400270  00003704 R_MIPS_26              000003e4   main
		new ExpectRelocationMIPS26(0x00400270, TARGET_SYMBOLS.get("main"), 0),
		// 0040028c  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x0040028c, 4, 0xffff, TARGET_SYMBOLS.get("sys_write")),
		// 00400290  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x00400290, 4, 0xffff, TARGET_SYMBOLS.get("sys_write"), 0),
		new ExpectRelocationRelativePC(0x0040029c, 4, 0xffff, TARGET_SYMBOLS.get("LAB_004002b4"),
			-4),
		// 004002b8  00002605 R_MIPS_HI16            00000000   errno
		new ExpectRelocationHighPair(0x004002b8, 4, 0xffff, TARGET_SYMBOLS.get("errno")),
		// 004002bc  00002606 R_MIPS_LO16            00000000   errno
		new ExpectRelocationLowPair(0x004002bc, 4, 0xffff, TARGET_SYMBOLS.get("errno"), 0),
		new ExpectRelocationRelativePC(0x004002c4, 4, 0xffff, TARGET_SYMBOLS.get("LAB_004002a4"),
			-4),
		// 004002dc  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x004002dc, 4, 0xffff, TARGET_SYMBOLS.get("fileno")),
		// 004002e0  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x004002e0, 4, 0xffff, TARGET_SYMBOLS.get("fileno"), 0),
		// 004002f8  00003005 R_MIPS_HI16            00000134   write
		new ExpectRelocationHighPair(0x004002f8, 4, 0xffff, TARGET_SYMBOLS.get("write")),
		// 004002fc  00003006 R_MIPS_LO16            00000134   write
		new ExpectRelocationLowPair(0x004002fc, 4, 0xffff, TARGET_SYMBOLS.get("write"), 0),
		new ExpectRelocationRelativePC(0x00400308, 4, 0xffff, TARGET_SYMBOLS.get("LAB_00400324"),
			-4),
		new ExpectRelocationRelativePC(0x00400328, 4, 0xffff, TARGET_SYMBOLS.get("LAB_00400314"),
			-4),
		// 0040033c  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x0040033c, 4, 0xffff, TARGET_SYMBOLS.get("fputc")),
		// 00400340  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x00400340, 4, 0xffff, TARGET_SYMBOLS.get("fputc"), 0),
		new ExpectRelocationRelativePC(0x00400374, 4, 0xffff, TARGET_SYMBOLS.get("LAB_00400394"),
			-4),
		// 00400380  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x00400380, 4, 0xffff, TARGET_SYMBOLS.get("putchar")),
		// 00400384  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x00400384, 4, 0xffff, TARGET_SYMBOLS.get("putchar"), 0),
		new ExpectRelocationRelativePC(0x00400394, 4, 0xffff, TARGET_SYMBOLS.get("LAB_004003e0"),
			-4),
		new ExpectRelocationRelativePC(0x004003bc, 4, 0xffff, TARGET_SYMBOLS.get("LAB_0040037c"),
			-4),
		// 004003c8  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x004003c8, 4, 0xffff, TARGET_SYMBOLS.get("putchar")),
		// 004003cc  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x004003cc, 4, 0xffff, TARGET_SYMBOLS.get("putchar"), 0),
		new ExpectRelocationRelativePC(0x004003d8, 4, 0xffff, TARGET_SYMBOLS.get("LAB_00400390"),
			-4),
		// 00400420  00003305 R_MIPS_HI16            0000020c   print_number
		new ExpectRelocationHighPair(0x00400420, 4, 0xffff, TARGET_SYMBOLS.get("print_number")),
		// 00400424  00003306 R_MIPS_LO16            0000020c   print_number
		new ExpectRelocationLowPair(0x00400424, 4, 0xffff, TARGET_SYMBOLS.get("print_number"), 0),

		// 00400434  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x00400434, 4, 0xffff, TARGET_SYMBOLS.get("putchar")),
		// 00400438  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x00400438, 4, 0xffff, TARGET_SYMBOLS.get("putchar"), 0),
		// 00400448  00003805 R_MIPS_HI16            00000590   isgraph
		new ExpectRelocationHighPair(0x00400448, 4, 0xffff, TARGET_SYMBOLS.get("isgraph")),
		// 0040044c  00003806 R_MIPS_LO16            00000590   isgraph
		new ExpectRelocationLowPair(0x0040044c, 4, 0xffff, TARGET_SYMBOLS.get("isgraph"), 0),
		new ExpectRelocationRelativePC(0x00400458, 4, 0xffff, TARGET_SYMBOLS.get("LAB_00400494"),
			-4),
		// 00400464  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x00400464, 4, 0xffff, TARGET_SYMBOLS.get("putchar")),
		// 00400468  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x00400468, 4, 0xffff, TARGET_SYMBOLS.get("putchar"), 0),
		// 00400478  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x00400478, 4, 0xffff, TARGET_SYMBOLS.get("putchar")),
		// 0040047c  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x0040047c, 4, 0xffff, TARGET_SYMBOLS.get("putchar"), 0),
		new ExpectRelocationRelativePC(0x0040048c, 4, 0xffff, TARGET_SYMBOLS.get("LAB_004004c8"),
			-4),
		// 00400498  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x00400498, 4, 0xffff, TARGET_SYMBOLS.get("putchar")),
		// 0040049c  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x0040049c, 4, 0xffff, TARGET_SYMBOLS.get("putchar"), 0),
		new ExpectRelocationRelativePC(0x004004a8, 4, 0xffff, TARGET_SYMBOLS.get("LAB_00400474"),
			-4),
		// 004004b4  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x004004b4, 4, 0xffff, TARGET_SYMBOLS.get("putchar")),
		// 004004b8  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x004004b8, 4, 0xffff, TARGET_SYMBOLS.get("putchar"), 0),
		new ExpectRelocationRelativePC(0x004004cc, 4, 0xffff, TARGET_SYMBOLS.get("LAB_00400510"),
			-4),
		new ExpectRelocationRelativePC(0x004004ec, 4, 0xffff, TARGET_SYMBOLS.get("LAB_004004b0"),
			-4),
		// 004004f8  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x004004f8, 4, 0xffff, TARGET_SYMBOLS.get("putchar")),
		// 004004fc  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x004004fc, 4, 0xffff, TARGET_SYMBOLS.get("putchar"), 0),
		new ExpectRelocationRelativePC(0x00400508, 4, 0xffff, TARGET_SYMBOLS.get("LAB_004004c4"),
			-4),

		new ExpectRelocationRelativePC(0x00400544, 4, 0xffff, TARGET_SYMBOLS.get("LAB_00400564"),
			-4),
		// 00400550  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x00400550, 4, 0xffff, TARGET_SYMBOLS.get("putchar")),
		// 00400554  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x00400554, 4, 0xffff, TARGET_SYMBOLS.get("putchar"), 0),
		new ExpectRelocationRelativePC(0x00400568, 4, 0xffff, TARGET_SYMBOLS.get("LAB_004005dc"),
			-4),
		// 00400570  00003c07 R_MIPS_GPREL16         00000000   COLUMNS
		new ExpectRelocationRelativeSymbol(0x00400570, 4, 0xffff, TARGET_SYMBOLS.get("COLUMNS"), 0,
			"_gp"),
		// 00400598  00002405 R_MIPS_HI16            00000000   s_ascii_properties
		new ExpectRelocationHighPair(0x00400598, 4, 0xffff,
			TARGET_SYMBOLS.get("s_ascii_properties")),
		// 0040059c  00002406 R_MIPS_LO16            00000000   s_ascii_properties
		new ExpectRelocationLowPair(0x0040059c, 4, 0xffff, TARGET_SYMBOLS.get("s_ascii_properties"),
			0),
		// 004005a8  00003b05 R_MIPS_HI16            000002a8   print_ascii_entry
		new ExpectRelocationHighPair(0x004005a8, 4, 0xffff,
			TARGET_SYMBOLS.get("print_ascii_entry")),
		// 004005ac  00003b06 R_MIPS_LO16            000002a8   print_ascii_entry
		new ExpectRelocationLowPair(0x004005ac, 4, 0xffff, TARGET_SYMBOLS.get("print_ascii_entry"),
			0),
		// 004005b8  00003c07 R_MIPS_GPREL16         00000000   COLUMNS
		new ExpectRelocationRelativeSymbol(0x004005b8, 4, 0xffff, TARGET_SYMBOLS.get("COLUMNS"), 0,
			"_gp"),
		new ExpectRelocationRelativePC(0x004005c8, 4, 0xffff, TARGET_SYMBOLS.get("LAB_0040054c"),
			-4),

		new ExpectRelocationRelativePC(0x004005d4, 4, 0xffff, TARGET_SYMBOLS.get("LAB_00400550"),
			-4),

		new ExpectRelocationRelativePC(0x00400604, 4, 0xffff, TARGET_SYMBOLS.get("LAB_0040062c"),
			-4),
		// 00400610  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x00400610, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_")),
		// 00400614  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x00400614, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_"), 1),
		new ExpectRelocationRelativePC(0x0040063c, 4, 0xffff, TARGET_SYMBOLS.get("LAB_00400664"),
			-4),
		// 00400648  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x00400648, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_")),
		// 0040064c  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x0040064c, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_"), 1),
		new ExpectRelocationRelativePC(0x00400674, 4, 0xffff, TARGET_SYMBOLS.get("LAB_0040069c"),
			-4),
		// 00400680  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x00400680, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_")),
		// 00400684  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x00400684, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_"), 1),
		new ExpectRelocationRelativePC(0x004006ac, 4, 0xffff, TARGET_SYMBOLS.get("LAB_004006d4"),
			-4),
		// 004006b8  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x004006b8, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_")),
		// 004006bc  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x004006bc, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_"), 1),
		new ExpectRelocationRelativePC(0x004006e4, 4, 0xffff, TARGET_SYMBOLS.get("LAB_0040070c"),
			-4),
		// 004006f0  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x004006f0, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_")),
		// 004006f4  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x004006f4, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_"), 1),
		new ExpectRelocationRelativePC(0x0040071c, 4, 0xffff, TARGET_SYMBOLS.get("LAB_00400744"),
			-4),
		// 00400728  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x00400728, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_")),
		// 0040072c  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x0040072c, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_"), 1),
		new ExpectRelocationRelativePC(0x00400754, 4, 0xffff, TARGET_SYMBOLS.get("LAB_0040077c"),
			-4),
		// 00400760  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x00400760, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_")),
		// 00400764  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x00400764, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_"), 1),
		new ExpectRelocationRelativePC(0x0040078c, 4, 0xffff, TARGET_SYMBOLS.get("LAB_004007b4"),
			-4),
		// 00400798  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x00400798, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_")),
		// 0040079c  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x0040079c, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_"), 1),
		new ExpectRelocationRelativePC(0x004007c4, 4, 0xffff, TARGET_SYMBOLS.get("LAB_004007ec"),
			-4),
		// 004007d0  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x004007d0, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_")),
		// 004007d4  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x004007d4, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_"), 1),
		new ExpectRelocationRelativePC(0x004007fc, 4, 0xffff, TARGET_SYMBOLS.get("LAB_00400824"),
			-4),
		// 00400808  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x00400808, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_")),
		// 0040080c  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x0040080c, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_"), 1),
		new ExpectRelocationRelativePC(0x00400834, 4, 0xffff, TARGET_SYMBOLS.get("LAB_0040085c"),
			-4),
		// 00400840  00003f05 R_MIPS_HI16            00000050   _ctype_
		new ExpectRelocationHighPair(0x00400840, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_")),
		// 00400844  00003f06 R_MIPS_LO16            00000050   _ctype_
		new ExpectRelocationLowPair(0x00400844, 4, 0xffff, TARGET_SYMBOLS.get("_ctype_"), 1),

		// .rel.text.nolibc_raise
		// 00400880  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x00400880, 4, 0xffff, TARGET_SYMBOLS.get("sys_getpid")),
		// 00400884  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x00400884, 4, 0xffff, TARGET_SYMBOLS.get("sys_getpid"), 0),
		// 00400898  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x00400898, 4, 0xffff, TARGET_SYMBOLS.get("sys_kill")),
		// 0040089c  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x0040089c, 4, 0xffff, TARGET_SYMBOLS.get("sys_kill"), 0),

		// .rel.text.nolibc_memcpy
		new ExpectRelocationRelativePC(0x004008c4, 4, 0xffff, TARGET_SYMBOLS.get("LAB_00400904"),
			-4),
		new ExpectRelocationRelativePC(0x004008d4, 4, 0xffff, TARGET_SYMBOLS.get("LAB_004008f4"),
			-4),
		new ExpectRelocationRelativePC(0x004008f4, 4, 0xffff, TARGET_SYMBOLS.get("LAB_004008dc"),
			-4),
		new ExpectRelocationRelativePC(0x0040090c, 4, 0xffff, TARGET_SYMBOLS.get("LAB_004008f4"),
			-4),
		// 0040091c  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x0040091c, 4, 0xffff,
			TARGET_SYMBOLS.get("_nolibc_memcpy_up")),
		// 00400920  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x00400920, 4, 0xffff, TARGET_SYMBOLS.get("_nolibc_memcpy_up"),
			0),
		new ExpectRelocationRelativePC(0x00400944, 4, 0xffff, TARGET_SYMBOLS.get("LAB_00400958"),
			-4),
		new ExpectRelocationRelativePC(0x0040095c, 4, 0xffff, TARGET_SYMBOLS.get("LAB_0040094c"),
			-4),

		// .rel.text.nolibc_abort
		// 00400974  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x00400974, 4, 0xffff, TARGET_SYMBOLS.get("sys_getpid")),
		// 00400978  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x00400978, 4, 0xffff, TARGET_SYMBOLS.get("sys_getpid"), 0),
		// 0040098c  00000305 R_MIPS_HI16            00000000   .text
		new ExpectRelocationHighPair(0x0040098c, 4, 0xffff, TARGET_SYMBOLS.get("sys_kill")),
		// 00400990  00000306 R_MIPS_LO16            00000000   .text
		new ExpectRelocationLowPair(0x00400990, 4, 0xffff, TARGET_SYMBOLS.get("sys_kill"), 0),
		new ExpectRelocationRelativePC(0x0040099c, 4, 0xffff, TARGET_SYMBOLS.get("LAB_0040099c"),
			-4),

		// .rel.rodata
		// 004009b0  00003802 R_MIPS_32              00000590   isgraph
		new ExpectRelocationAbsolute(0x004009b0, 4, TARGET_SYMBOLS.get("isgraph"), 0),
		// 004009b8  00003a02 R_MIPS_32              00000600   isprint
		new ExpectRelocationAbsolute(0x004009b8, 4, TARGET_SYMBOLS.get("isprint"), 0),
		// 004009c0  00003e02 R_MIPS_32              00000520   iscntrl
		new ExpectRelocationAbsolute(0x004009c0, 4, TARGET_SYMBOLS.get("iscntrl"), 0),
		// 004009c8  00002d02 R_MIPS_32              00000670   isspace
		new ExpectRelocationAbsolute(0x004009c8, 4, TARGET_SYMBOLS.get("isspace"), 0),
		// 004009d0  00002c02 R_MIPS_32              00000638   ispunct
		new ExpectRelocationAbsolute(0x004009d0, 4, TARGET_SYMBOLS.get("ispunct"), 0),
		// 004009d8  00003902 R_MIPS_32              000004b0   isalnum
		new ExpectRelocationAbsolute(0x004009d8, 4, TARGET_SYMBOLS.get("isalnum"), 0),
		// 004009e0  00003502 R_MIPS_32              000004e8   isalpha
		new ExpectRelocationAbsolute(0x004009e0, 4, TARGET_SYMBOLS.get("isalpha"), 0),
		// 004009e8  00003d02 R_MIPS_32              00000558   isdigit
		new ExpectRelocationAbsolute(0x004009e8, 4, TARGET_SYMBOLS.get("isdigit"), 0),
		// 004009f0  00003402 R_MIPS_32              000006a8   isupper
		new ExpectRelocationAbsolute(0x004009f0, 4, TARGET_SYMBOLS.get("isupper"), 0),
		// 004009f8  00002b02 R_MIPS_32              000005c8   islower
		new ExpectRelocationAbsolute(0x004009f8, 4, TARGET_SYMBOLS.get("islower"), 0));

	@Override
	protected String getProgramName() {
		return "src/test/resources/ascii-table/reference/elf_linux_freestanding/mipsel/ascii-table.elf.gzf";
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
