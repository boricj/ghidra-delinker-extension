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
package ghidra.app.util.exporter.elf.relocs;

import java.util.List;
import java.util.Map;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.relocobj.RelocationEntry;
import ghidra.program.model.relocobj.RelocationGang;
import ghidra.program.model.relocobj.RelocationGangRoleDescriptor;
import ghidra.program.model.relocobj.RelocationGroup;
import ghidra.util.classfinder.ExtensionPoint;
import net.boricj.bft.elf.ElfFile;
import net.boricj.bft.elf.ElfSection;
import net.boricj.bft.elf.constants.ElfSectionType;
import net.boricj.bft.elf.sections.ElfSymbolTable;
import net.boricj.bft.elf.sections.ElfSymbolTable.ElfSymbol;

public interface ElfRelocationTableBuilder extends ExtensionPoint {
	public ElfSection buildGroups(ElfFile elf,
			ElfSymbolTable symtab, ElfSection section, byte[] bytes,
			AddressSetView addressSet, List<RelocationGroup> groups,
			Map<RelocationGroup, ElfSymbol> groupsToSymbols, MessageLog log);

	public boolean canBuild(ElfFile elf, ElfSectionType sectionType);

	public static String generateSectionName(ElfSection section, String prefix) {
		String name = section.getName();
		return String.format("%s%s%s", prefix, (name.startsWith(".") ? "" : "."), name);
	}

	public static void logUnknownRelocation(ElfSection section, RelocationGroup group,
			RelocationGang gang, RelocationEntry entry, MessageLog log) {
		int gangIndex = group.getGangs().indexOf(gang);
		RelocationGangRoleDescriptor descriptor =
			gangIndex >= 0 ? RelocationGangRoleDescriptor.derive(group, gangIndex)
					: RelocationGangRoleDescriptor.UNKNOWN;
		String msg = String.format(
			"Unknown grouped relocation %s type=%s width=%d bitmask=%d at %s", 
			group.getExpression().getKind(), descriptor, gang.getWidth(),
			gang.getBitmask(), entry.address());
		log.appendMsg(section.getName(), msg);
	}
}
