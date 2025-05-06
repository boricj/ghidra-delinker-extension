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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.BinaryOperator;
import java.util.function.Supplier;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;

public class SymbolInformationCollector
		implements Collector<Symbol, Map<Address, Set<Symbol>>, Map<Address, SymbolInformation>> {

	private static final Set<Characteristics> CHARACTERISTICS = Set.of(Characteristics.UNORDERED);

	private final SymbolPreference preference;

	public SymbolInformationCollector(SymbolPreference preference) {
		this.preference = preference;
	}

	@Override
	public Supplier<Map<Address, Set<Symbol>>> supplier() {
		return () -> new HashMap<>();
	}

	@Override
	public BiConsumer<Map<Address, Set<Symbol>>, Symbol> accumulator() {
		return (map, symbol) -> {
			Address address = symbol.getAddress();
			Set<Symbol> symbols = map.get(address);
			if (symbols == null) {
				symbols = new HashSet<>();
				map.put(address, symbols);
			}
			symbols.add(symbol);
		};
	}

	@Override
	public BinaryOperator<Map<Address, Set<Symbol>>> combiner() {
		return (map1, map2) -> {
			map2.forEach((address, symbols) -> {
				Set<Symbol> existingSymbols = map1.get(address);
				if (existingSymbols == null) {
					map1.put(address, symbols);
				}
				else {
					existingSymbols.addAll(symbols);
				}
			});
			return map1;
		};
	}

	@Override
	public java.util.function.Function<Map<Address, Set<Symbol>>, Map<Address, SymbolInformation>> finisher() {
		return map -> {
			return map.entrySet()
					.stream()
					.collect(Collectors.toMap(
						entry -> entry.getKey(),
						entry -> {
							Set<Symbol> symbols = entry.getValue();
							Symbol symbol = SymbolPreference.PRIMARY.pick(symbols);
							String name = preference.pick(symbols).getName(true);
							return new SymbolInformation(symbol, name);
						}));
		};
	}

	@Override
	public Set<Characteristics> characteristics() {
		return CHARACTERISTICS;
	}

	public static java.util.function.Function<Set<Symbol>, Set<Symbol>> postProcessIdentity() {
		return symbols -> symbols;
	}
}
