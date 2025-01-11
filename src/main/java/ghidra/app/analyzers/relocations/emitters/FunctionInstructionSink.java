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
package ghidra.app.analyzers.relocations.emitters;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;

/**
 * This interface is used for processing the instructions of a function in
 * ascending address order.
 */
public interface FunctionInstructionSink {
	public abstract boolean process(Instruction instruction, AddressSetView relocatable)
			throws MemoryAccessException, CancelledException;

	public default boolean isReferenceInteresting(Reference reference, AddressSetView relocatable) {
		boolean interesting = reference.isPrimary();
		interesting &= !reference.isStackReference() && !reference.isRegisterReference();
		if (!relocatable.isEmpty()) {
			interesting &= relocatable.contains(reference.getToAddress());
		}
		return interesting;
	}
}
