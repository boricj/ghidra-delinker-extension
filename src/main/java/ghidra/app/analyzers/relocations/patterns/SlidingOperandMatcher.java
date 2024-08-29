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

import static ghidra.app.util.ProgramUtil.getBitmask;
import static ghidra.app.util.ProgramUtil.getInstructionOperandMask;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.ProgramUtilities;
import ghidra.util.DataConverter;

public abstract class SlidingOperandMatcher implements OperandMatcher {
	public static final OperandMatcher SIGNED_1BYTE =
		new Signed(new Byte[] { -1 });
	public static final OperandMatcher SIGNED_2BYTES =
		new Signed(new Byte[] { -1, -1 });
	public static final OperandMatcher SIGNED_4BYTES =
		new Signed(new Byte[] { -1, -1, -1, -1 });
	public static final OperandMatcher SIGNED_8BYTES =
		new Signed(new Byte[] { -1, -1, -1, -1, -1, -1, -1, -1 });

	public static final OperandMatcher UNSIGNED_1BYTE =
		new Unsigned(new Byte[] { -1 });
	public static final OperandMatcher UNSIGNED_2BYTES =
		new Unsigned(new Byte[] { -1, -1 });
	public static final OperandMatcher UNSIGNED_4BYTES =
		new Unsigned(new Byte[] { -1, -1, -1, -1 });
	public static final OperandMatcher UNSIGNED_8BYTES =
		new Unsigned(new Byte[] { -1, -1, -1, -1, -1, -1, -1, -1 });

	public static class Signed extends SlidingOperandMatcher {
		public Signed(Byte[] bytes) {
			super(bytes);
		}

		@Override
		public OperandMatch createMatch(Instruction instruction, int operandIndex, int offset)
				throws MemoryAccessException {
			int size = getMaskLength();
			DataConverter dc = ProgramUtilities.getDataConverter(instruction.getProgram());
			long value = dc.getSignedValue(instruction.getBytes(), offset, size);

			return new OperandMatch(operandIndex, offset, size, getBitmask(size), value);
		}
	}

	public static class Unsigned extends SlidingOperandMatcher {
		public Unsigned(Byte[] bytes) {
			super(bytes);
		}

		@Override
		public OperandMatch createMatch(Instruction instruction, int operandIndex, int offset)
				throws MemoryAccessException {
			int size = getMaskLength();
			DataConverter dc = ProgramUtilities.getDataConverter(instruction.getProgram());
			long value = dc.getValue(instruction.getBytes(), offset, size);

			return new OperandMatch(operandIndex, offset, size, getBitmask(size), value);
		}
	}

	private final List<Byte> operandMask;

	public SlidingOperandMatcher(Byte[] bytes) {
		this.operandMask = Arrays.asList(bytes);
	}

	@Override
	public Optional<OperandMatch> match(Instruction instruction, int operandIndex)
			throws MemoryAccessException {
		List<Byte> instructionOperandMask =
			Arrays.asList(getInstructionOperandMask(instruction, operandIndex));
		int offset = Collections.indexOfSubList(instructionOperandMask, operandMask);

		if (offset == -1) {
			return Optional.empty();
		}

		// Check that every byte before the mask are zeroes.
		for (int index = 0; index < offset; index++) {
			if (instructionOperandMask.get(index) != 0x00) {
				return Optional.empty();
			}
		}

		// Check that every byte after the mask are zeroes.
		final int size = instructionOperandMask.size();
		for (int index = offset + operandMask.size(); index < size; index++) {
			if (instructionOperandMask.get(index) != 0x00) {
				return Optional.empty();
			}
		}

		return Optional.of(createMatch(instruction, operandIndex, offset));
	}

	@Override
	public int getMaskLength() {
		return operandMask.size();
	}

	public abstract OperandMatch createMatch(Instruction instruction, int opreandIndex, int offset)
			throws MemoryAccessException;
}
