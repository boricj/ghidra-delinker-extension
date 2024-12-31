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
package ghidra.app.util.exporter.coff.relocs;

import java.util.List;
import java.util.Map;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.relocobj.Relocation;
import ghidra.util.classfinder.ExtensionPoint;
import net.boricj.bft.coff.CoffSection;
import net.boricj.bft.coff.CoffSymbolTable;
import net.boricj.bft.coff.CoffSymbolTable.CoffSymbol;
import net.boricj.bft.coff.constants.CoffMachine;

public interface CoffRelocationTableBuilder extends ExtensionPoint {
	public void build(CoffSymbolTable symtab, CoffSection section, byte[] bytes,
			AddressSetView addressSet, List<Relocation> relocations,
			Map<String, CoffSymbol> symbolsByName, MessageLog log);

	public boolean canBuild(CoffMachine machine);

	public static void logUnknownRelocation(CoffSection section, Relocation relocation,
			MessageLog log) {
		String name = relocation.getClass().getSimpleName();
		String msg = String.format("Unknown relocation %s width %d bitmask %d at %s", name,
			relocation.getWidth(), relocation.getBitmask(), relocation.getAddress());
		log.appendMsg(section.getName(), msg);
	}
}
