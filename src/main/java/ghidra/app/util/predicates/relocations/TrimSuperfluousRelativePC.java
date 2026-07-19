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
package ghidra.app.util.predicates.relocations;

import java.util.function.Predicate;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.relocobj.RelocationExpressionKind;
import ghidra.program.model.relocobj.RelocationGroup;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

public class TrimSuperfluousRelativePC implements Predicate<RelocationGroup> {
	private final Program program;
	private final AddressSetView selection;

	public TrimSuperfluousRelativePC(Program program, AddressSetView selection) {
		this.program = program;
		this.selection = selection;
	}

	@Override
	public boolean test(RelocationGroup group) {
		if (group.getExpression().getKind() != RelocationExpressionKind.PC_RELATIVE) {
			return true;
		}

		if (group.getGangs().isEmpty() || group.getGangs().get(0).getEntries().isEmpty()) {
			return true;
		}

		Address relocationAddress = group.getGangs().get(0).getEntries().get(0).address();
		RelocationTable relocationTable = RelocationTable.get(program);
		if (!relocationTable.isTransparentRelativePC(relocationAddress)) {
			return true;
		}

		ReferenceManager referenceManager = program.getReferenceManager();
		Listing listing = program.getListing();
		CodeUnit codeUnit = listing.getCodeUnitContaining(relocationAddress);
		if (codeUnit == null) {
			return true;
		}

		Address fromAddress = codeUnit.getAddress();
		AddressRange fromRange = selection.getRangeContaining(fromAddress);
		if (fromRange == null) {
			return true;
		}

		for (Reference reference : referenceManager.getReferencesFrom(fromAddress)) {
			if (!reference.isPrimary()) {
				continue;
			}

			Address toAddress = reference.getToAddress();
			if (!fromRange.contains(toAddress)) {
				return true;
			}
		}

		return false;
	}
}
