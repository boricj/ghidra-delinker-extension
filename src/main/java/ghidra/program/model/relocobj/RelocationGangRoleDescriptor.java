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

/**
 * Derived role-like descriptors for relocation gangs.
 */
public enum RelocationGangRoleDescriptor {
	ABSOLUTE,
	PC_RELATIVE,
	HIGH_PAIR,
	LOW_PAIR,
	REGION_RELATIVE,
	SYMBOL_RELATIVE,
	UNKNOWN;

	public static RelocationGangRoleDescriptor derive(RelocationGroup group, int gangIndex) {
		RelocationGang gang = group.getGangs().get(gangIndex);
		RelocationExpressionKind kind = group.getExpression().getKind();

		if (kind == RelocationExpressionKind.PC_RELATIVE) {
			return PC_RELATIVE;
		}
		if (kind == RelocationExpressionKind.SYMBOL_RELATIVE) {
			return SYMBOL_RELATIVE;
		}
		if (kind != RelocationExpressionKind.ABSOLUTE) {
			return UNKNOWN;
		}

		if (group.getGangs().size() == 2 && gang.getWidth() == 4 && gang.getBitmask() == 0xffffL) {
			if (gangIndex == 0) {
				return HIGH_PAIR;
			}
			if (gangIndex == 1) {
				return LOW_PAIR;
			}
		}

		if (gang.getWidth() == 4 && gang.getBitmask() == 0x3ffffffL) {
			return REGION_RELATIVE;
		}

		return ABSOLUTE;
	}
}
