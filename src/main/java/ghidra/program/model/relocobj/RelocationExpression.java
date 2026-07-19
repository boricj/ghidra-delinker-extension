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
	private final String symbolName;
	private final String qualifier;

	private RelocationExpression(RelocationExpressionKind kind, String symbolName,
			String qualifier) {
		this.kind = Objects.requireNonNull(kind);
		this.symbolName = symbolName;
		this.qualifier = qualifier;
	}

	public static RelocationExpression absolute() {
		return new RelocationExpression(RelocationExpressionKind.ABSOLUTE, null, null);
	}

	public static RelocationExpression pcRelative() {
		return new RelocationExpression(RelocationExpressionKind.PC_RELATIVE, null, null);
	}

	public static RelocationExpression regionRelative() {
		return new RelocationExpression(RelocationExpressionKind.REGION_RELATIVE, null, null);
	}

	public static RelocationExpression relativeToSymbol(String symbolName) {
		Objects.requireNonNull(symbolName);
		return new RelocationExpression(RelocationExpressionKind.RELATIVE_TO_SYMBOL, symbolName,
			null);
	}

	public static RelocationExpression qualifiedSymbol(String qualifier, String symbolName) {
		Objects.requireNonNull(qualifier);
		Objects.requireNonNull(symbolName);
		return new RelocationExpression(RelocationExpressionKind.QUALIFIED_SYMBOL, symbolName,
			qualifier);
	}

	public RelocationExpressionKind getKind() {
		return kind;
	}

	public String getSymbolName() {
		return symbolName;
	}

	public String getQualifier() {
		return qualifier;
	}
}
