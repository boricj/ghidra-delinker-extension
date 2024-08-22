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
package ghidra.app.util.visibility;

import java.util.function.Predicate;
import java.util.regex.Pattern;

import ghidra.program.model.symbol.Symbol;

public class IsSymbolNameMatchingRegex implements Predicate<Symbol> {
	public static final String DEFAULT_PATTERN = "^switchD_.+::switchdataD_.+$";;

	private final Pattern pattern;

	public IsSymbolNameMatchingRegex(String regex) {
		this.pattern = Pattern.compile(regex);
	}

	@Override
	public boolean test(Symbol symbol) {
		return pattern.matcher(symbol.getName(true)).matches();
	}
}
