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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.TreeMap;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

public class RelocationTable {
	public static record RelocationLocation(long groupId, int gangIndex, int entryIndex) {}

	public Program currentProgram;
	private LinkedHashMap<Long, RelocationGroup> groupsById = new LinkedHashMap<>();
	private NavigableMap<Address, List<RelocationLocation>> groupLocationsByAddress =
		new TreeMap<>();
	private Map<Address, Boolean> transparentRelativePCByAddress = new HashMap<>();
	private long nextGroupId = 1;

	public RelocationTable(Program currentProgram) {
		this.currentProgram = currentProgram;
	}

	public void clear() {
		synchronized (groupsById) {
			groupsById.clear();
			groupLocationsByAddress.clear();
			transparentRelativePCByAddress.clear();
			nextGroupId = 1;
		}
	}

	public void clear(AddressSetView addressSet) {
		List<Long> listGroups;
		synchronized (groupsById) {
			listGroups = groupsById.values()
					.stream()
					.filter(g -> containsGroup(addressSet, g))
					.map(g -> g.getGroupId())
					.collect(Collectors.toList());
		}

		for (long groupId : listGroups) {
			deleteGroup(groupId);
		}
	}

	private static boolean containsGroup(AddressSetView addressSet, RelocationGroup group) {
		for (RelocationGang gang : group.getGangs()) {
			for (RelocationEntry entry : gang.getEntries()) {
				if (addressSet.contains(entry.address())) {
					return true;
				}
			}
		}

		return false;
	}

	public RelocationGroup addSingleEntryGroup(RelocationExpression expression,
			Address target, long groupAddend, RelocationTypeTag relocationType, int width,
			long bitmask,
			Address entryAddress, long entryAddend) {
		RelocationEntry entry = new RelocationEntry(entryAddress, entryAddend);
		RelocationGang gang = new RelocationGang(relocationType, width, bitmask, List.of(entry));
		RelocationGroup group =
			new RelocationGroup(0, expression, target, groupAddend, List.of(gang));
		return addGroup(group);
	}

	public RelocationGroup appendEntryToGroup(long groupId, RelocationTypeTag relocationType,
			int width,
			long bitmask, Address entryAddress, long entryAddend) {
		RelocationGroup existing = groupsById.get(groupId);
		if (existing == null) {
			throw new IllegalArgumentException("Unknown relocation group id " + groupId);
		}
		List<RelocationGang> gangs = new ArrayList<>(existing.getGangs());
		RelocationEntry newEntry = new RelocationEntry(entryAddress, entryAddend);

		int sameTypeGangIndex = -1;
		for (int i = 0; i < gangs.size(); i++) {
			RelocationGang gang = gangs.get(i);
			if (gang.getRelocationType().equals(relocationType) && gang.getWidth() == width &&
				gang.getBitmask() == bitmask) {
				sameTypeGangIndex = i;
				if (gang.getEntries().contains(newEntry)) {
					return existing;
				}
				break;
			}
		}

		removeGroupLocations(groupId);

		if (sameTypeGangIndex >= 0) {
			RelocationGang gang = gangs.get(sameTypeGangIndex);
			List<RelocationEntry> entries = new ArrayList<>(gang.getEntries());
			entries.add(newEntry);
			gang = new RelocationGang(relocationType, width, bitmask, entries);
			gangs.set(sameTypeGangIndex, gang);
		}
		else {
			gangs.add(new RelocationGang(relocationType, width, bitmask, List.of(newEntry)));
		}

		RelocationGroup updated = new RelocationGroup(groupId, existing.getExpression(),
			existing.getTarget(), existing.getAddend(), gangs);
		groupsById.put(groupId, updated);
		indexGroupLocations(updated);
		return updated;
	}

	private void indexGroupLocations(RelocationGroup group) {
		for (int gangIndex = 0; gangIndex < group.getGangs().size(); gangIndex++) {
			RelocationGang gang = group.getGangs().get(gangIndex);
			for (int entryIndex = 0; entryIndex < gang.getEntries().size(); entryIndex++) {
				RelocationEntry entry = gang.getEntries().get(entryIndex);
				List<RelocationLocation> refs = groupLocationsByAddress
						.computeIfAbsent(entry.address(), a -> new ArrayList<>());
				refs.add(new RelocationLocation(group.getGroupId(), gangIndex, entryIndex));
			}
		}
	}

	private void removeGroupLocations(long groupId) {
		List<Address> empty = new ArrayList<>();
		for (Map.Entry<Address, List<RelocationLocation>> entry : groupLocationsByAddress
				.entrySet()) {
			List<RelocationLocation> refs = entry.getValue();
			refs.removeIf(ref -> ref.groupId() == groupId);
			if (refs.isEmpty()) {
				empty.add(entry.getKey());
			}
		}

		for (Address address : empty) {
			groupLocationsByAddress.remove(address);
		}
	}

	public RelocationGroup addGroup(RelocationGroup group) {
		synchronized (groupsById) {
			RelocationGroup normalized = group;
			if (group.getGroupId() <= 0) {
				normalized = new RelocationGroup(nextGroupId++, group.getExpression(),
					group.getTarget(), group.getAddend(), group.getGangs());
			}

			RelocationGroup previous = groupsById.get(normalized.getGroupId());
			if (previous != null) {
				if (previous != normalized && !previous.equals(normalized)) {
					throw new IllegalArgumentException(
						"Non-equivalent relocation group already exists with id " +
							normalized.getGroupId());
				}

				return previous;
			}

			groupsById.put(normalized.getGroupId(), normalized);
			indexGroupLocations(normalized);
			return normalized;
		}
	}

	public RelocationGroup getRelocationGroup(long groupId) {
		synchronized (groupsById) {
			return groupsById.get(groupId);
		}
	}

	public void deleteGroup(long groupId) {
		synchronized (groupsById) {
			RelocationGroup removed = groupsById.remove(groupId);
			if (removed != null) {
				removeGroupLocations(groupId);
			}
		}
	}

	public Iterator<RelocationGroup> getRelocationGroups() {
		synchronized (groupsById) {
			return new ArrayList<>(groupsById.values()).iterator();
		}
	}

	public Iterator<RelocationGroup> getRelocationGroups(AddressSetView addressSet) {
		final Iterator<RelocationGroup> iterator = getRelocationGroups();
		final Stream<RelocationGroup> stream = StreamSupport.stream(
			Spliterators.spliteratorUnknownSize(iterator, Spliterator.ORDERED), false);
		return stream.filter(g -> containsGroup(addressSet, g)).iterator();
	}

	public Iterator<RelocationGroup> getRelocationGroups(AddressSetView addressSet,
			Predicate<RelocationGroup> predicate) {
		final Iterator<RelocationGroup> iteratorAddressSet = getRelocationGroups(addressSet);
		final Stream<RelocationGroup> stream = StreamSupport.stream(
			Spliterators.spliteratorUnknownSize(iteratorAddressSet, Spliterator.ORDERED), false);
		return stream.filter(predicate).iterator();
	}

	public List<RelocationLocation> getRelocationLocationsAt(Address address) {
		synchronized (groupsById) {
			List<RelocationLocation> refs = groupLocationsByAddress.get(address);
			if (refs == null) {
				return List.of();
			}

			return Collections.unmodifiableList(refs);
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

	public void addAbsoluteGroup(Address address, int width, long bitmask, Address target,
			long addend) {
		addSingleEntryGroup(RelocationExpression.absolute(), target, addend,
			RelocationTypeTag.ABSOLUTE, width, bitmask, address, 0);
	}

	public RelocationGroup addHighPairGroup(Address address, int width, long bitmask,
			Address target) {
		synchronized (groupsById) {
			for (RelocationGroup group : groupsById.values()) {
				if (group.getExpression().getKind() != RelocationExpressionKind.ABSOLUTE ||
					group.getAddend() != 0 || !group.getTarget().equals(target)) {
					continue;
				}

				for (RelocationGang gang : group.getGangs()) {
					if (gang.getRelocationType() != RelocationTypeTag.HIGH_PAIR ||
						gang.getWidth() != width || gang.getBitmask() != bitmask) {
						continue;
					}

					for (RelocationEntry entry : gang.getEntries()) {
						if (entry.address().equals(address) && entry.localAddend() == 0) {
							return group;
						}
					}
				}
			}
		}

		return addSingleEntryGroup(RelocationExpression.absolute(), target, 0,
			RelocationTypeTag.HIGH_PAIR, width, bitmask, address, 0);
	}

	public RelocationGroup addLowPairGroup(long groupId, Address address, int width,
			long bitmask, long addend) {
		return appendEntryToGroup(groupId, RelocationTypeTag.LOW_PAIR, width, bitmask, address,
			addend);
	}

	public void addMIPS26Group(Address address, Address target, long addend) {
		addSingleEntryGroup(RelocationExpression.absolute(), target, addend,
			RelocationTypeTag.MIPS_26, 4, 0x3ffffffL, address, 0);
	}

	public void addRelativePCGroup(Address address, int width, long bitmask, Address target,
			long addend, boolean isTransparent, long trailingBytes) {
		RelocationGroup group = addSingleEntryGroup(RelocationExpression.pcRelative(), target,
			addend, RelocationTypeTag.PC_RELATIVE, width, bitmask, address, trailingBytes);
		transparentRelativePCByAddress.put(address, isTransparent);
		if (group == null) {
			throw new IllegalStateException();
		}
	}


	public boolean isTransparentRelativePC(Address address) {
		synchronized (groupsById) {
			Boolean transparent = transparentRelativePCByAddress.get(address);
			if (transparent != null) {
				return transparent;
			}

			return true;
		}
	}

	public void addRelativeSymbolGroup(Address address, int width, long bitmask, Address target,
			long addend, String relativeTarget) {
		addSingleEntryGroup(RelocationExpression.relativeToSymbol(relativeTarget), target,
			addend, RelocationTypeTag.RELATIVE_SYMBOL, width, bitmask, address, 0);
	}
}
