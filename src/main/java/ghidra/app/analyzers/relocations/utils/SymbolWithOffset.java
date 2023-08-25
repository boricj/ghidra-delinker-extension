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
package ghidra.app.analyzers.relocations.utils;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class SymbolWithOffset {
	public String name;
	public long address;
	public long offset;

	public SymbolWithOffset(String name, long address, long offset) {
		this.name = name;
		this.address = address;
		this.offset = offset;
	}

	public static SymbolWithOffset get(Program program, Address fromAddress, Address toAddress) {
		for (Reference reference : program.getReferenceManager().getReferencesFrom(fromAddress)) {
			if (reference.getToAddress().equals(toAddress)) {
				return get(program, reference);
			}
		}

		return null;
	}

	public static SymbolWithOffset get(Program program, Reference reference) {
		Address address = reference.getToAddress();
		long offset = 0;
		Symbol symbol = program.getSymbolTable().getSymbol(reference);

		// Normalize references to base of symbol, if any.
		CodeUnit codeUnit = program.getListing().getCodeUnitContaining(address);
		if (codeUnit != null) {
			address = codeUnit.getMinAddress();
			offset = reference.getToAddress().subtract(address);
			symbol = program.getSymbolTable().getPrimarySymbol(address);
		}

		if (symbol == null) {
			return null;
		}

		return new SymbolWithOffset(symbol.getName(true), address.getOffset(), offset);
	}
}
