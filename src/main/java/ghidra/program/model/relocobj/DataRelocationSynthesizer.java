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
package ghidra.program.model.relocobj;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.task.TaskMonitor;

public interface DataRelocationSynthesizer extends ExtensionPoint {
	public void processPointer(Program program, AddressSetView set, Data pointer,
			RelocationTable relocationTable, TaskMonitor monitor, MessageLog log)
			throws MemoryAccessException;

	public boolean canAnalyze(Program program);
}
