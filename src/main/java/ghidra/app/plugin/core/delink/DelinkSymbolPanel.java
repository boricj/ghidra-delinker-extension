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

import java.awt.BorderLayout;

import javax.swing.JPanel;
import javax.swing.ListSelectionModel;

import ghidra.app.plugin.core.symtable.SymbolRowObject;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraThreadedTablePanel;

public class DelinkSymbolPanel extends JPanel {
	private DelinkPlugin plugin;
	private DelinkSymbolTableModel model;

	private GhidraThreadedTablePanel<SymbolRowObject> threadedTablePanel;
	private GhidraTable symTable;

	public DelinkSymbolPanel(DelinkPlugin plugin, DelinkSymbolTableModel model,
			final PluginTool tool) {
		super(new BorderLayout());

		this.plugin = plugin;
		this.model = model;

		threadedTablePanel = new GhidraThreadedTablePanel<>(model);

		symTable = threadedTablePanel.getTable();
		symTable.setRowSelectionAllowed(true);
		symTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		GoToService goToService = tool.getService(GoToService.class);
		symTable.installNavigation(goToService, goToService.getDefaultNavigatable());

		add(threadedTablePanel, BorderLayout.CENTER);
	}
}
