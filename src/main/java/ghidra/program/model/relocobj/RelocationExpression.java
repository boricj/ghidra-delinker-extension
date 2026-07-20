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

import java.util.Objects;

/**
 * Semantic descriptor for relocation groups.
 */
public class RelocationExpression {
	private final RelocationExpressionKind kind;
	private final RelocationExpressionBase base;
	private final String symbolName;

	private RelocationExpression(RelocationExpressionKind kind, RelocationExpressionBase base,
			String symbolName) {
		this.kind = Objects.requireNonNull(kind);
		this.base = Objects.requireNonNull(base);
		this.symbolName = symbolName;
	}

	public static RelocationExpression absolute() {
		return new RelocationExpression(RelocationExpressionKind.ABSOLUTE,
			RelocationExpressionBase.DIRECT, null);
	}

	public static RelocationExpression pcRelative() {
		return new RelocationExpression(RelocationExpressionKind.PC_RELATIVE,
			RelocationExpressionBase.DIRECT, null);
	}

	public static RelocationExpression regionRelative() {
		return new RelocationExpression(RelocationExpressionKind.REGION_RELATIVE,
			RelocationExpressionBase.DIRECT, null);
	}

	public static RelocationExpression relativeToSymbol(String symbolName) {
		Objects.requireNonNull(symbolName);
		return new RelocationExpression(RelocationExpressionKind.SYMBOL_RELATIVE,
			RelocationExpressionBase.DIRECT, symbolName);
	}

	public static RelocationExpression qualifiedSymbol(RelocationExpressionBase base,
			String symbolName) {
		Objects.requireNonNull(base);
		Objects.requireNonNull(symbolName);
		return new RelocationExpression(RelocationExpressionKind.SYMBOL_RELATIVE, base,
			symbolName);
	}

	public RelocationExpressionKind getKind() {
		return kind;
	}

	public RelocationExpressionBase getBase() {
		return base;
	}

	public String getSymbolName() {
		return symbolName;
	}

	public RelocationExpressionBase getQualifier() {
		return base;
	}
}
