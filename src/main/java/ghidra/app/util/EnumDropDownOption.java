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
package ghidra.app.util;

import java.util.Arrays;
import java.util.stream.Collectors;

public class EnumDropDownOption<T extends Enum<T>> extends DropDownOption<T> {
	public EnumDropDownOption(String group, String name, Class<T> class_, T defaultValue) {
		super(group, name, Arrays.stream(class_.getEnumConstants())
				.collect(Collectors.toMap(v -> v, T::toString)),
			class_, defaultValue);
	}
}
