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
package ghidra.program.model.relocobj;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.TreeMap;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.DataConverter;

public class RelocationTable {
	public Program currentProgram;
	private TreeMap<Address, Relocation> relocations = new TreeMap<>();

	public RelocationTable(Program currentProgram) {
		this.currentProgram = currentProgram;
	}

	public Relocation getRelocationAt(Address address) {
		synchronized (relocations) {
			return relocations.get(address);
		}
	}

	public void clear() {
		synchronized (relocations) {
			relocations.clear();
		}
	}

	public void clear(AddressSetView addressSet) {
		List<Relocation> listRelocations;
		synchronized (relocations) {
			Iterator<Relocation> iterator = getRelocations(addressSet);
			listRelocations = StreamSupport.stream(
				Spliterators.spliteratorUnknownSize(iterator, Spliterator.ORDERED), false)
					.collect(Collectors.toList());
		}

		for (Relocation relocation : listRelocations) {
			relocation.delete();
		}
	}

	public byte[] getOriginalBytes(AddressSetView addressSet, DataConverter dc,
			boolean encodeAddend, boolean adjustRelativeWithTargetSize)
			throws MemoryAccessException {
		return getOriginalBytes(addressSet, dc, encodeAddend, adjustRelativeWithTargetSize,
			relocation -> true);
	}

	public byte[] getOriginalBytes(AddressSetView addressSet, DataConverter dc,
			boolean encodeAddend, boolean adjustRelativeWithTargetSize,
			Predicate<Relocation> predicate) throws MemoryAccessException {
		AddressFactory addressFactory = currentProgram.getAddressFactory();
		MemoryBlock memoryBlock = currentProgram.getMemory().getBlock(addressSet.getMinAddress());
		if (memoryBlock == null ||
			!addressFactory.getAddressSet(memoryBlock.getStart(), memoryBlock.getEnd())
					.contains(addressSet)) {
			throw new IllegalArgumentException(
				"Address set doesn't match any specific memory block");
		}

		byte[] bytes = new byte[(int) addressSet.getNumAddresses()];
		if (memoryBlock.isInitialized()) {
			int offset = 0;
			for (AddressRange range : addressSet.getAddressRanges()) {
				int length = (int) range.getLength();
				memoryBlock.getBytes(range.getMinAddress(), bytes, offset, length);
				offset += length;
			}

			for (Relocation relocation : (Iterable<Relocation>) () -> getRelocations(addressSet,
				predicate)) {
				if (predicate.test(relocation)) {
					relocation.unapply(bytes, addressSet, dc, encodeAddend,
						adjustRelativeWithTargetSize);
				}
			}
		}

		return bytes;
	}

	public Iterator<Relocation> getRelocations() {
		synchronized (relocations) {
			// FIXME: Implement proper synchronized relocation iterator.
			return relocations.values().iterator();
		}
	}

	public Iterator<Relocation> getRelocations(AddressSetView iteratorAddressSet) {
		Address cursor;

		synchronized (relocations) {
			cursor = relocations.ceilingKey(iteratorAddressSet.getMinAddress());
			while (cursor != null && !iteratorAddressSet.contains(cursor)) {
				cursor = relocations.higherKey(cursor);
			}
		}

		final Address iteratorCursor = cursor;

		return new Iterator<Relocation>() {
			Address cursor = iteratorCursor;
			AddressSetView addressSet = iteratorAddressSet;

			@Override
			public boolean hasNext() {
				return cursor != null;
			}

			@Override
			public Relocation next() {
				if (cursor == null) {
					throw new NoSuchElementException();
				}

				Relocation value = null;

				synchronized (relocations) {
					value = relocations.get(cursor);

					do {
						cursor = relocations.higherKey(cursor);
					}
					while (cursor != null && !addressSet.contains(cursor));
				}

				return value;
			}
		};
	}

	public Iterator<Relocation> getRelocations(AddressSetView addressSet,
			Predicate<Relocation> predicate) {
		final Iterator<Relocation> iteratorAddressSet = getRelocations(addressSet);
		final Stream<Relocation> stream = StreamSupport.stream(
			Spliterators.spliteratorUnknownSize(iteratorAddressSet, Spliterator.ORDERED), false);
		return stream.filter(predicate).iterator();
	}

	protected Relocation add(Relocation newRelocation) {
		Address address = newRelocation.getAddress();

		synchronized (relocations) {
			Relocation relocation = relocations.getOrDefault(address, newRelocation);
			if (!relocation.equals(newRelocation)) {
				String msg = String.format(
					"Non-equivalent relocation already exists at address %s for symbol %s", address,
					relocation.getSymbolName());
				throw new IllegalArgumentException(msg);
			}

			relocations.put(address, relocation);
			return relocation;
		}
	}

	protected void delete(Relocation relocation) {
		synchronized (relocations) {
			relocations.remove(relocation.getAddress());
		}
	}

	// FIXME: Relocation table lives outside program.
	private static final Map<Long, RelocationTable> singletons = new HashMap<>();

	public static RelocationTable get(Program program) {
		long uniqueProgramID = program.getUniqueProgramID();

		synchronized (singletons) {
			if (!singletons.containsKey(uniqueProgramID)) {
				singletons.put(uniqueProgramID, new RelocationTable(program));
			}
			return singletons.get(uniqueProgramID);
		}
	}

	public RelocationAbsolute addAbsolute(Address address, int length, String name, long offset) {
		RelocationAbsolute rel =
			new RelocationAbsolute(this, address, length, name, offset);
		return (RelocationAbsolute) add(rel);
	}

	public RelocationAbsolute addAbsolute(Address address, int width, long bitmask,
			String symbolName, long addend) {
		RelocationAbsolute rel =
			new RelocationAbsolute(this, address, width, bitmask, symbolName, addend);
		return (RelocationAbsolute) add(rel);
	}

	public RelocationHighPair addHighPair(Address address, int width, long bitmask,
			String symbolName) {
		RelocationHighPair rel = new RelocationHighPair(this, address, width, bitmask, symbolName);
		return (RelocationHighPair) add(rel);
	}

	public RelocationLowPair addLowPair(Address address, int width, long bitmask,
			RelocationHighPair relocationHi, long addend) {
		RelocationLowPair rel =
			new RelocationLowPair(this, address, width, bitmask, relocationHi, addend);
		rel = (RelocationLowPair) add(rel);
		relocationHi.addRelocationLo(rel);
		return rel;
	}

	public RelocationMIPS26 addMIPS26(Address address, String symbolName, long addend) {
		RelocationMIPS26 rel =
			new RelocationMIPS26(this, address, symbolName, addend);
		return (RelocationMIPS26) add(rel);
	}

	public RelocationRelativePC addRelativePC(Address address, int width, String symbolName,
			long addend) {
		RelocationRelativePC rel =
			new RelocationRelativePC(this, address, width, symbolName, addend);
		return (RelocationRelativePC) add(rel);
	}

	public RelocationRelativePC addRelativePC(Address address, int width, String symbolName,
			long addend, boolean isTransparent) {
		RelocationRelativePC rel =
			new RelocationRelativePC(this, address, width, symbolName, addend, isTransparent);
		return (RelocationRelativePC) add(rel);
	}

	public RelocationRelativePC addRelativePC(Address address, int width, long bitmask,
			String symbolName, long addend) {
		RelocationRelativePC rel =
			new RelocationRelativePC(this, address, width, bitmask, symbolName, addend);
		return (RelocationRelativePC) add(rel);
	}

	public RelocationRelativePC addRelativePC(Address address, int width, long bitmask,
			String symbolName, long addend, boolean isTransparent) {
		RelocationRelativePC rel =
			new RelocationRelativePC(this, address, width, bitmask, symbolName, addend,
				isTransparent);
		return (RelocationRelativePC) add(rel);
	}

	public RelocationRelativeSymbol addRelativeSymbol(Address address, int width, String symbolName,
			long addend, String relativeSymbolName) {
		RelocationRelativeSymbol rel = new RelocationRelativeSymbol(this, address, width,
			symbolName, addend, relativeSymbolName);
		return (RelocationRelativeSymbol) add(rel);
	}

	public RelocationRelativeSymbol addRelativeSymbol(Address address, int width, long bitmask,
			String symbolName, long addend, String relativeSymbolName) {
		RelocationRelativeSymbol rel = new RelocationRelativeSymbol(this, address, width, bitmask,
			symbolName, addend, relativeSymbolName);
		return (RelocationRelativeSymbol) add(rel);
	}
}
