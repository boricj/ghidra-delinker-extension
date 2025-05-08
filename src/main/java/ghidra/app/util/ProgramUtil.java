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
package ghidra.app.util;

import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.Spliterators;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import org.apache.commons.lang3.ArrayUtils;

import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Mask;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.relocobj.Relocation;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.DataConverter;
import ghidra.util.bean.opteditor.OptionsVetoException;

public abstract class ProgramUtil {
	private final static Pattern PATTERN_ADDRESS_SET = Pattern.compile(
		"^\\s*\\[(\\s*\\[\\s*([\\w:]+)\\s*,\\s*([\\w:]+)\\s*\\]\\s*,?)?(?:\\s*\\[\\s*[\\w:]+\\s*,\\s*[\\w:]+\\s*\\]\\s*)?(?:,\\s*\\[\\s*[\\w:]+\\s*,\\s*[\\w:]+\\s*\\]\\s*)*\\s*\\]\\s*$");

	public static Program getProgram(DomainObject domainObj) {
		if (!(domainObj instanceof Program)) {
			return null;
		}
		return (Program) domainObj;
	}

	public static Byte[] getInstructionOperandMask(Instruction instruction, int operandIndex) {
		InstructionPrototype prototype = instruction.getPrototype();
		Mask valueMask = prototype.getOperandValueMask(operandIndex);
		return ArrayUtils.toObject(valueMask.getBytes());
	}

	public static byte[] getBytes(Program program, AddressSetView addressSet)
			throws MemoryAccessException {
		MemoryBlock memoryBlock = program.getMemory().getBlock(addressSet.getMinAddress());
		byte[] bytes = new byte[(int) addressSet.getNumAddresses()];
		int offset = 0;

		for (AddressRange range : addressSet.getAddressRanges()) {
			int length = (int) range.getLength();
			memoryBlock.getBytes(range.getMinAddress(), bytes, offset, length);
			offset += length;
		}

		return bytes;
	}

	public static void patchBytes(byte[] buffer, AddressSetView addressSet, DataConverter dc,
			Relocation relocation, long value) {
		patchBytes(buffer, addressSet, relocation.getAddress(), dc, relocation.getWidth(),
			relocation.getBitmask(), value);
	}

	public static void patchBytes(byte[] buffer, AddressSetView addressSet, Address address,
			DataConverter dc, int width, long bitmask, long value) {
		checkBitmaskContiguous(width, bitmask);
		checkBitmaskValue(width, bitmask, value);

		int shift = Long.numberOfTrailingZeros(bitmask);
		int offset = (int) ProgramUtil.getOffsetWithinAddressSet(addressSet, address, width);

		long data = dc.getValue(buffer, offset, width) & ~bitmask;
		data = data | ((value << shift) & bitmask);
		dc.putValue(data, width, buffer, offset);
	}

	public static void checkBitmaskContiguous(int width, long bitmask) {
		long bitcount = Long.bitCount(bitmask);
		long highestOneBit = Long.numberOfTrailingZeros(Long.highestOneBit(bitmask));
		long lowestOneBit = Long.numberOfTrailingZeros(Long.lowestOneBit(bitmask));

		if (bitcount == 0) {
			throw new IllegalArgumentException("bitmask is empty");
		}
		if (bitcount != (1 + highestOneBit - lowestOneBit)) {
			throw new IllegalArgumentException("bitmask isn't contiguous");
		}
		if (highestOneBit > width * 8) {
			throw new IllegalArgumentException("bitmask wider than relocation width");
		}
	}

	public static void checkBitmaskValue(int width, long bitmask, long value) {
		long highestOneBit = Long.numberOfTrailingZeros(Long.highestOneBit(bitmask));

		if (value >= 0 && (value >> highestOneBit) != 0) {
			throw new IllegalArgumentException("value must fit inside bitmask");
		}
		else if (value < 0 && (value >> highestOneBit) != -1L) {
			throw new IllegalArgumentException("value must fit inside bitmask");
		}
	}

	public static long getBitmask(int width) {
		if (width > 8) {
			throw new IllegalArgumentException("width must fit within 64 bit value");
		}
		else if (width == 8) {
			return 0xffffffffffffffffL;
		}
		else {
			return (1L << (width * 8)) - 1;
		}
	}

	public static long getOffsetWithinAddressSet(AddressSetView addressSet, Address address) {
		Address minAddress = addressSet.getMinAddress();
		AddressSetView intersectedRange = addressSet.intersectRange(minAddress, address);
		return intersectedRange.getNumAddresses() - 1;
	}

	public static long getOffsetWithinAddressSet(AddressSetView addressSet, Address address,
			int width) {
		if (!addressSet.contains(address, address.add(width - 1))) {
			throw new IllegalArgumentException("buffer does not contain relocation");
		}

		return getOffsetWithinAddressSet(addressSet, address);
	}

	public static Map<Address, SymbolInformation> getSectionSymbols(Program program,
			AddressSetView sectionSet, SymbolPreference symbolNamePreference) {
		return StreamSupport
				.stream(program.getSymbolTable().getAllSymbols(true).spliterator(), false)
				.filter(symbol -> sectionSet.contains(symbol.getAddress()))
				.collect(new SymbolInformationCollector(symbolNamePreference));
	}

	public static Map<Address, SymbolInformation> getExternalSymbols(Program program,
			AddressSetView fileSet, SymbolPreference symbolNamePreference) {
		SymbolTable symbolTable = program.getSymbolTable();
		RelocationTable relocationTable = RelocationTable.get(program);

		Set<Address> externalRelocationTargets = StreamSupport.stream(
			Spliterators.spliteratorUnknownSize(relocationTable.getRelocations(), 0), false)
				.filter(r -> fileSet.contains(r.getAddress()) && !fileSet.contains(r.getTarget()))
				.map(r -> r.getTarget())
				.collect(Collectors.toSet());

		return StreamSupport
				.stream(symbolTable.getAllSymbols(true).spliterator(), false)
				.filter(symbol -> externalRelocationTargets.contains(symbol.getAddress()))
				.collect(new SymbolInformationCollector(symbolNamePreference));
	}

	public static <T> boolean checkDuplicateSymbols(Stream<T> symbols,
			java.util.function.Function<T, String> asString, MessageLog log) {
		Map<String, Long> duplicates =
			symbols.collect(Collectors.groupingBy(asString, Collectors.counting()))
					.entrySet()
					.stream()
					.filter(entry -> entry.getValue() > 1)
					.collect(Collectors.toMap(entry -> entry.getKey(), entry -> entry.getValue()));

		duplicates.forEach((key, count) -> {
			log.appendMsg(String.format("Duplicate symbol name '%s' (%d instances)", key, count));
		});

		return duplicates.isEmpty();
	}

	public static AddressSet parseAddressSet(String str, AddressFactory addressFactory) {
		Matcher matcher = PATTERN_ADDRESS_SET.matcher(str);
		if (!matcher.matches()) {
			throw new OptionsVetoException("Invalid address set format");
		}

		AddressSet addressSet = new AddressSet();
		while (matcher.group(1) != null) {
			Address start = addressFactory.getAddress(matcher.group(2));
			Address end = addressFactory.getAddress(matcher.group(3));
			addressSet.add(start, end);

			str = str.substring(0, matcher.start(1)) + str.substring(matcher.end(1));
			matcher.reset(str);
			matcher.matches();
		}

		return addressSet;
	}

	public static String serializeAddressSet(AddressSetView addressSet) {
		StringBuilder sb = new StringBuilder();
		Iterator<AddressRange> iterator = addressSet.iterator();

		sb.append("[");
		while (iterator.hasNext()) {
			AddressRange range = iterator.next();
			sb.append("[")
					.append(range.getMinAddress())
					.append(", ")
					.append(range.getMaxAddress())
					.append("]");
			if (iterator.hasNext()) {
				sb.append(", ");
			}
		}
		sb.append("]");

		return sb.toString();
	}
}
