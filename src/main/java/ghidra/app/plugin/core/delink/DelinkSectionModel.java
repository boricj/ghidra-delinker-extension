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
package ghidra.app.plugin.core.delink;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class DelinkSectionModel {
	private Program program;
	private String name;
	private AddressSetView addressSetView;

	private Set<Symbol> internalSymbols;
	private Set<Symbol> externalSymbols;
	private Set<Reference> references;

	DelinkSectionModel(Program program, String name, AddressSetView addressSetView) {
		this.program = program;
		this.name = name;
		this.addressSetView = addressSetView;
	}

	public String getName() {
		return name;
	}

	public AddressSetView getAddressSetView() {
		return addressSetView;
	}

	public Set<Symbol> getInternalSymbols() {
		return internalSymbols;
	}

	public Set<Symbol> getExternalSymbols() {
		return externalSymbols;
	}

	public Set<Reference> getReferences() {
		return references;
	}

	@Override
	public boolean equals(Object o) {
		if (o == null || o.getClass() != getClass()) {
			return false;
		}

		DelinkSectionModel other = (DelinkSectionModel) o;
		return program.equals(other.program) &&
			name.equals(other.name) &&
			addressSetView.equals(other.addressSetView);
	}

	@Override
	public int hashCode() {
		return Objects.hash(program, name, addressSetView);
	}

	public void delink(AddressSetView target) {
		internalSymbols = new HashSet<>();
		externalSymbols = new HashSet<>();
		references = new HashSet<>();

		Map<Reference, Symbol> internalToInternal = new HashMap<>();
		Map<Reference, Symbol> internalToExternal = new HashMap<>();
		Map<Reference, Symbol> externalToInternal = new HashMap<>();
		SymbolTable symbolTable = program.getSymbolTable();

		for (Symbol symbol : symbolTable.getAllSymbols(true)) {
			Address symbolAddress = symbol.getAddress();

			if (addressSetView.contains(symbolAddress)) {
				for (Reference reference : symbol.getReferences()) {
					if (!reference.isPrimary()) {
						continue;
					}

					Address fromAddress = reference.getFromAddress();
					if (addressSetView.contains(fromAddress)) {
						internalToInternal.put(reference, symbol);
					}
					else if (target.contains(fromAddress)) {
						externalToInternal.put(reference, symbol);
					}
				}
			}
			else if (target.contains(symbolAddress)) {
				for (Reference reference : symbol.getReferences()) {
					if (!reference.isPrimary()) {
						continue;
					}

					Address fromAddress = reference.getFromAddress();
					if (addressSetView.contains(fromAddress)) {
						internalToExternal.put(reference, symbol);
					}
				}
			}
		}

		internalSymbols.addAll(internalToInternal.values());
		externalSymbols.addAll(internalToExternal.values());
		internalSymbols.addAll(externalToInternal.values());

		references.addAll(internalToInternal.keySet());
		references.addAll(internalToExternal.keySet());
	}
}
