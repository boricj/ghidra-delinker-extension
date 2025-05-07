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

public class RelocationTarget {
	private Address address;
	private long offset;
	private Address destination;

	public RelocationTarget(Address address, long offset) {
		this.address = address;
		this.offset = offset;
		this.destination = address;
	}

	public RelocationTarget(Address address, long offset, Address destination) {
		this.address = address;
		this.offset = offset;
		this.destination = destination;
	}

	public Address getAddress() {
		return address;
	}

	public long getOffset() {
		return offset;
	}

	public Address getDestination() {
		return destination;
	}

	public RelocationTarget withDestination(Address newDestination) {
		return new RelocationTarget(address, offset, newDestination);
	}

	public static RelocationTarget find(Program program, Address fromAddress, Address toAddress) {
		for (Reference reference : program.getReferenceManager().getReferencesFrom(fromAddress)) {
			if (reference.getToAddress().equals(toAddress)) {
				return get(program, reference);
			}
		}

		return null;
	}

	public static RelocationTarget get(Program program, Reference reference) {
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

		return new RelocationTarget(address, offset);
	}
}
