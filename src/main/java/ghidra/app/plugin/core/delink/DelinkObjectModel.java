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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class DelinkObjectModel {
	private Program program;
	private String name;
	private AddressSetView target;

	private Collection<DelinkSectionModel> sections;
	private Set<Symbol> internalSymbols;
	private Set<Symbol> externalSymbols;

	DelinkObjectModel(Program program, String name, AddressSetView target) {
		this.program = program;
		this.name = name;
		this.target = target;

		this.sections = new ArrayList<>();
	}

	public String getName() {
		return name;
	}

	public Collection<DelinkSectionModel> getSections() {
		return sections;
	}

	public AddressSetView getTarget() {
		return target;
	}

	@Override
	public boolean equals(Object o) {
		if (o == null || o.getClass() != getClass()) {
			return false;
		}

		DelinkObjectModel other = (DelinkObjectModel) o;
		return program.equals(other.program) &&
			name.equals(other.name) &&
			target.equals(other.target) &&
			sections.equals(other.sections);
	}

	@Override
	public int hashCode() {
		return Objects.hash(program, name, target, sections);
	}

	public void addSection(String name, AddressSetView addressSetView) {
		DelinkSectionModel section = new DelinkSectionModel(program, name, addressSetView);
		sections.add(section);
	}

	public void delink() {
		internalSymbols = new HashSet<>();
		externalSymbols = new HashSet<>();

		for (DelinkSectionModel section : sections) {
			section.delink(target);

			externalSymbols.addAll(section.getExternalSymbols());
			internalSymbols.addAll(section.getInternalSymbols());
			externalSymbols.removeAll(internalSymbols);
		}
	}

	public Set<Symbol> getExternalSymbols() {
		return externalSymbols;
	}

	public Set<Symbol> getInternalSymbols() {
		return internalSymbols;
	}

	public Stream<Reference> getAllReferencesAsStream() {
		Stream<Reference> references = Stream.empty();
		for (DelinkSectionModel section : getSections()) {
			references = Stream.concat(references, section.getReferences().stream());
		}
		return references;
	}
}
