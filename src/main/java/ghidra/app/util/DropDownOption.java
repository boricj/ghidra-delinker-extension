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

import java.awt.Component;
import java.util.HashMap;
import java.util.Map;

import javax.swing.JComboBox;

public class DropDownOption<T> extends Option {
	private final Map<T, String> values;
	private final Map<String, T> reverseValues = new HashMap<>();
	private final Class<T> class_;
	private final T defaultValue;
	private final JComboBox<String> comp;

	public DropDownOption(String group, String name, Map<T, String> values, Class<T> class_,
			T defaultValue) {
		super(group, name, defaultValue);

		this.values = values;
		for (Map.Entry<T, String> entry : values.entrySet()) {
			this.reverseValues.put(entry.getValue(), entry.getKey());
		}

		this.defaultValue = defaultValue;
		this.class_ = class_;

		this.comp = new JComboBox<String>(values.values().toArray(new String[values.size()]));
		this.comp.setSelectedItem(values.get(defaultValue));
	}

	@Override
	public Component getCustomEditorComponent() {
		return comp;
	}

	@Override
	public Option copy() {
		return new DropDownOption<T>(getGroup(), getName(), values, class_, defaultValue);
	}

	@Override
	public T getValue() {
		return reverseValues.get(comp.getSelectedItem());
	}

	@Override
	public Class<?> getValueClass() {
		return class_;
	}
}
