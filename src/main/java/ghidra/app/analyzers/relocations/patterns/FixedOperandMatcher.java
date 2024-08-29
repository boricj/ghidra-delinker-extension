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
package ghidra.app.analyzers.relocations.patterns;

import static ghidra.app.util.ProgramUtil.getInstructionOperandMask;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;

public abstract class FixedOperandMatcher implements OperandMatcher {
	private final List<Byte> operandMask;

	public FixedOperandMatcher(Byte[] bytes) {
		this.operandMask = Arrays.asList(bytes);
	}

	@Override
	public Optional<OperandMatch> match(Instruction instruction, int operandIndex)
			throws MemoryAccessException {
		List<Byte> instructionOperandMask =
			Arrays.asList(getInstructionOperandMask(instruction, operandIndex));

		if (Collections.indexOfSubList(instructionOperandMask, operandMask) != 0 ||
			instructionOperandMask.size() != operandMask.size()) {
			return Optional.empty();
		}

		return Optional.of(createMatch(instruction, operandIndex));
	}

	@Override
	public int getMaskLength() {
		return operandMask.size();
	}

	public abstract OperandMatch createMatch(Instruction instruction, int operandIndex)
			throws MemoryAccessException;
}
