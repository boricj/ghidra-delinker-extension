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
package ghidra.app.plugin.core.delink;

import javax.swing.JComponent;
import javax.swing.JTabbedPane;

import ghidra.framework.plugintool.ComponentProviderAdapter;

public class DelinkObjectProvider extends ComponentProviderAdapter {
	private DelinkPlugin plugin;
	private DelinkObjectModel model;
	private JTabbedPane panel;

	public DelinkObjectProvider(DelinkPlugin plugin, DelinkObjectModel model) {
		super(plugin.getTool(), "Delinker Provider", plugin.getName());
		this.plugin = plugin;
		this.model = model;
		this.panel = new JTabbedPane(JTabbedPane.BOTTOM);
		/*
				for (DelinkSectionModel section : this.model.getSections()) {
					String paneTitle = String.format("%s %s", section.getName(), section.getAddressRange());
					DelinkSymbolPane pane = new DelinkSymbolPane(this.plugin, section);
		
					this.panel.addTab(paneTitle, pane);
				}
		
				String title = String.format("%s %s", this.model.getName(), this.model.getTarget());
				setTitle(title);
				setTransient();
				addToTool();
				setVisible(true);
		*/
		DelinkSymbolTableModel symbolTableModel =
			new DelinkSymbolTableModel(this, plugin.getTool());
		DelinkSymbolPanel symbolPanel =
			new DelinkSymbolPanel(plugin, symbolTableModel, plugin.getTool());
		this.panel.addTab("Symbols", symbolPanel);

		DelinkReferenceTableModel referenceTableModel =
			new DelinkReferenceTableModel(this, plugin.getTool(), plugin.getCurrentProgram());
		DelinkReferencePanel referencePanel =
			new DelinkReferencePanel(plugin, referenceTableModel, plugin.getTool());
		this.panel.addTab("References", referencePanel);

		String title = String.format("%s %s", this.model.getName(), this.model.getTarget());
		setTitle(title);
		setTransient();
		addToTool();
		setVisible(true);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	@Override
	public void closeComponent() {
		plugin.providerDismissed(this);
	}

	public DelinkObjectModel getModel() {
		return model;
	}

	public void update() {
	}

	public void dispose() {
		tool.removeComponentProvider(this);
	}
}
