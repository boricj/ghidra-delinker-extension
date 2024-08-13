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
import java.util.function.Function;
import java.util.regex.Pattern;

import ghidra.program.model.symbol.Symbol;

public enum SymbolPreference {
	PRIMARY("Primary symbol", SymbolPreference::pickPrimary),
	MSVC("MSVC (Visual C++ name mangling, underscore prefix)", SymbolPreference::pickMsvc),
	ITANIUM_ABI("Modern LLVM/GCC (Itanium C++ ABI name mangling, primary symbol)", SymbolPreference::pickItaniumAbi);

	private static final Pattern ITANIUM_MANGLING = Pattern.compile("_Z\\d+.*");
	private static final Pattern MSVC_MANGLING = Pattern.compile("\\?.*");

	private final String label;
	private final Function<Collection<Symbol>, Symbol> picker;

	SymbolPreference(String label, Function<Collection<Symbol>, Symbol> picker) {
		this.label = label;
		this.picker = picker;
	}

	@Override
	public String toString() {
		return label;
	}

	public Symbol pick(Collection<Symbol> candidates) {
		return picker.apply(candidates);
	}

	private static Symbol pickPrimary(Collection<Symbol> symbols) {
		return symbols.stream().filter(s -> s.isPrimary()).findAny().orElseThrow();
	}

	private static Symbol pickItaniumAbi(Collection<Symbol> symbols) {
		Symbol primary = pickPrimary(symbols);
		return symbols.stream()
				.filter(s -> ITANIUM_MANGLING.matcher(s.getName(true)).matches())
				.findAny()
				.orElse(primary);
	}

	private static Symbol pickMsvc(Collection<Symbol> symbols) {
		return symbols.stream()
				.filter(s -> MSVC_MANGLING.matcher(s.getName(true)).matches())
				.findAny()
				.orElseGet(() -> pickUnderscorePrefix(symbols));
	}

	private static Symbol pickUnderscorePrefix(Collection<Symbol> symbols) {
		Symbol primary = pickPrimary(symbols);
		String underscoredPrimary = "_" + primary.getName(true);
		return symbols.stream()
				.filter(s -> s.getName(true).equals(underscoredPrimary))
				.findAny()
				.orElse(primary);
	}
}
