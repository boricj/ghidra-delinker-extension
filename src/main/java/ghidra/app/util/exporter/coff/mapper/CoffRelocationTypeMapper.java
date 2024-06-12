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
package ghidra.app.util.exporter.coff.mapper;

import java.util.List;

import ghidra.app.util.exporter.coff.CoffRelocatableRelocationTable;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.relocobj.Relocation;
import ghidra.util.classfinder.ExtensionPoint;

public interface CoffRelocationTypeMapper extends ExtensionPoint {
	public void process(CoffRelocatableRelocationTable relTable, List<Relocation> relocations,
			MessageLog log);

	public boolean canProcess(int machine);
}
