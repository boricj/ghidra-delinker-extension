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
package ghidra.app.util.predicates.visibility;

import java.util.function.Predicate;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

public class IsSymbolInsideFunction implements Predicate<Symbol> {
	@Override
	public boolean test(Symbol symbol) {
		Address address = symbol.getAddress();
		Program program = symbol.getProgram();
		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunctionContaining(address);

		return function != null && !function.getEntryPoint().equals(address);
	}
}
