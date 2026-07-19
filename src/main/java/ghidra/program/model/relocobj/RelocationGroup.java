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

import java.util.List;
import java.util.Objects;

import ghidra.program.model.address.Address;

/**
 * One semantic relocation expression encoded by one or more gangs.
 */
public class RelocationGroup {
	private final long groupId;
	private final RelocationExpression expression;
	private final Address target;
	private final long addend;
	private final List<RelocationGang> gangs;

	public RelocationGroup(long groupId, RelocationExpression expression, Address target,
			long addend, List<RelocationGang> gangs) {
		this.groupId = groupId;
		this.expression = Objects.requireNonNull(expression);
		this.target = Objects.requireNonNull(target);
		this.addend = addend;
		this.gangs = List.copyOf(gangs);
	}

	public long getGroupId() {
		return groupId;
	}

	public RelocationExpression getExpression() {
		return expression;
	}

	public Address getTarget() {
		return target;
	}

	public long getAddend() {
		return addend;
	}

	public List<RelocationGang> getGangs() {
		return gangs;
	}
}
