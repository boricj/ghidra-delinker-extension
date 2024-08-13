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

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Spliterators;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.relocobj.Relocation;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.program.model.symbol.Symbol;

public class ProgramUtil {
	public static Program getProgram(DomainObject domainObj) {
		if (!(domainObj instanceof Program)) {
			return null;
		}
		return (Program) domainObj;
	}

	public static long getOffsetWithinAddressSet(AddressSetView addressSet, Address address) {
		Address minAddress = addressSet.getMinAddress();
		AddressSetView intersectedRange = addressSet.intersectRange(minAddress, address);
		return intersectedRange.getNumAddresses() - 1;
	}

	public static Map<String, Symbol> getSectionSymbols(Program program,
			AddressSetView sectionSet, SymbolPreference symbolNamePreference) {
		return getSymbols(program, s -> sectionSet.contains(s.getAddress()), symbolNamePreference,
			false);
	}

	public static Map<String, Symbol> getExternalSymbols(Program program, AddressSetView fileSet,
			SymbolPreference symbolNamePreference) {
		Map<String, Symbol> externalSymbols =
			getSymbols(program, s -> !fileSet.contains(s.getAddress()), symbolNamePreference, true);
		// Filtering out internal symbols with identical names is required for dealing with thunks.
		Map<String, Symbol> internalSymbols =
			getSymbols(program, s -> fileSet.contains(s.getAddress()), symbolNamePreference, false);

		RelocationTable relocationTable = RelocationTable.get(program);
		Stream<Relocation> relocations = StreamSupport.stream(
			Spliterators.spliteratorUnknownSize(relocationTable.getRelocations(fileSet), 0), false);
		return relocations.map(r -> r.getSymbolName())
				.filter(s -> s != null && externalSymbols.containsKey(s) &&
					!internalSymbols.containsKey(s))
				.distinct()
				.collect(Collectors.toMap(Function.identity(), s -> externalSymbols.get(s)));
	}

	private static Map<String, Symbol> getSymbols(Program program, Predicate<Symbol> predicate,
			SymbolPreference symbolNamePreference, boolean allowDuplicates) {
		Stream<Symbol> symbols =
			StreamSupport.stream(program.getSymbolTable().getAllSymbols(true).spliterator(), false);
		Collection<List<Symbol>> symbolsPerAddress =
			symbols.filter(predicate)
					.collect(Collectors.groupingBy(Symbol::getAddress, Collectors.toList()))
					.values();
		Stream<List<Symbol>> intermediate = symbolsPerAddress.stream()
				.map(candidates -> List.of(SymbolPreference.PRIMARY.pick(candidates),
					symbolNamePreference.pick(candidates)));

		if (allowDuplicates) {
			return intermediate.collect(
				Collectors.toMap(l -> l.get(0).getName(true), l -> l.get(1), (a, b) -> {
					if (!a.isPrimary()) {
						return a;
					}
					else {
						return b;
					}
				}));
		}
		else {
			return intermediate
					.collect(Collectors.toMap(l -> l.get(0).getName(true), l -> l.get(1)));
		}
	}
}
