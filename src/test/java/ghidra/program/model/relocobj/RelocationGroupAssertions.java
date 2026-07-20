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

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import ghidra.program.model.address.AddressSetView;

public final class RelocationGroupAssertions {
	public static record ExpectedEntry(long address, long localAddend) {
	}

	public static record ExpectedGang(RelocationGangRoleDescriptor type, int width, long bitmask,
			List<ExpectedEntry> entries) {
	}

	public static record ExpectedGroup(RelocationExpressionKind expressionKind, long target,
			long addend, List<ExpectedGang> gangs) {
	}

	private RelocationGroupAssertions() {
	}

	public static ExpectedEntry entry(long address, long localAddend) {
		return new ExpectedEntry(address, localAddend);
	}

	public static ExpectedGang gang(RelocationGangRoleDescriptor type, int width, long bitmask,
			ExpectedEntry... entries) {
		return new ExpectedGang(type, width, bitmask, List.of(entries));
	}

	public static ExpectedGroup group(RelocationExpressionKind expressionKind, long target,
			long addend, ExpectedGang... gangs) {
		return new ExpectedGroup(expressionKind, target, addend, List.of(gangs));
	}

	public static void assertGroups(RelocationTable relocationTable, AddressSetView set,
			List<ExpectedGroup> expectedGroups) {
		List<RelocationGroup> actualGroups = new ArrayList<>();
		relocationTable.getRelocationGroups(set).forEachRemaining(actualGroups::add);

		List<ExpectedGroup> expectedSorted = expectedGroups.stream()
				.sorted(Comparator.comparingLong((ExpectedGroup g) -> firstAddress(g))
						.thenComparing(ExpectedGroup::expressionKind)
						.thenComparingLong(ExpectedGroup::target)
						.thenComparingLong(ExpectedGroup::addend))
				.toList();
		List<RelocationGroup> actualSorted = actualGroups.stream()
				.sorted(Comparator.comparingLong((RelocationGroup g) -> firstAddress(g))
						.thenComparing(g -> g.getExpression().getKind())
						.thenComparingLong(g -> g.getTarget().getOffset())
						.thenComparingLong(RelocationGroup::getAddend))
				.toList();

		assertEquals("group count", expectedSorted.size(), actualSorted.size());
		for (int groupIndex = 0; groupIndex < expectedSorted.size(); groupIndex++) {
			ExpectedGroup expectedGroup = expectedSorted.get(groupIndex);
			RelocationGroup actualGroup = actualSorted.get(groupIndex);
			String context = "group[" + groupIndex + "]";

			assertEquals(context + " expression kind", expectedGroup.expressionKind(),
				actualGroup.getExpression().getKind());
			assertEquals(context + " target", expectedGroup.target(),
				actualGroup.getTarget().getOffset());
			assertEquals(context + " addend", expectedGroup.addend(), actualGroup.getAddend());

			List<ExpectedGang> expectedGangs = expectedGroup.gangs();
			List<RelocationGang> actualGangs = actualGroup.getGangs();
			assertEquals(context + " gang count", expectedGangs.size(), actualGangs.size());
			for (int gangIndex = 0; gangIndex < expectedGangs.size(); gangIndex++) {
				ExpectedGang expectedGang = expectedGangs.get(gangIndex);
				RelocationGang actualGang = actualGangs.get(gangIndex);
				String gangContext = context + " gang[" + gangIndex + "]";

				assertEquals(gangContext + " type", expectedGang.type(),
					RelocationGangRoleDescriptor.derive(actualGroup, gangIndex));
				assertEquals(gangContext + " width", expectedGang.width(), actualGang.getWidth());
				assertEquals(gangContext + " bitmask", expectedGang.bitmask(),
					actualGang.getBitmask());

				List<ExpectedEntry> expectedEntries = expectedGang.entries();
				List<RelocationEntry> actualEntries = actualGang.getEntries();
				assertEquals(gangContext + " entry count", expectedEntries.size(),
					actualEntries.size());
				for (int entryIndex = 0; entryIndex < expectedEntries.size(); entryIndex++) {
					ExpectedEntry expectedEntry = expectedEntries.get(entryIndex);
					RelocationEntry actualEntry = actualEntries.get(entryIndex);
					String entryContext = gangContext + " entry[" + entryIndex + "]";

					assertEquals(entryContext + " address", expectedEntry.address(),
						actualEntry.address().getOffset());
					assertEquals(entryContext + " local addend", expectedEntry.localAddend(),
						actualEntry.localAddend());
				}
			}
		}
	}

	private static long firstAddress(ExpectedGroup group) {
		return group.gangs().stream()
				.flatMap(gang -> gang.entries().stream())
				.mapToLong(ExpectedEntry::address)
				.min()
				.orElse(Long.MAX_VALUE);
	}

	private static long firstAddress(RelocationGroup group) {
		return group.getGangs().stream()
				.flatMap(gang -> gang.getEntries().stream())
				.mapToLong(entry -> entry.address().getOffset())
				.min()
				.orElse(Long.MAX_VALUE);
	}
}
