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
package ghidra.app.plugin.core.relocobj;

import java.awt.BorderLayout;
import java.awt.Dimension;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.ToolTipManager;

import ghidra.app.plugin.core.relocobj.RelocationTableModel.RelocationRowObject;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.GhidraThreadedTablePanel;

class RelocationProvider extends ComponentProviderAdapter {
	private GhidraTable table;
	private RelocationTableModel tableModel;
	private RelocationTableSynthesizedPlugin plugin;
	private JPanel mainPanel;
	private Program currentProgram;
	private GhidraTableFilterPanel<RelocationRowObject> tableFilterPanel;
	private GhidraThreadedTablePanel<RelocationRowObject> threadedPanel;

	RelocationProvider(RelocationTableSynthesizedPlugin plugin) {
		super(plugin.getTool(), "Relocation Table (synthesized)", plugin.getName());
		this.plugin = plugin;
		mainPanel = buildMainPanel();
		addToTool();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	@Override
	public void componentShown() {
		tableModel.setProgram(currentProgram);
	}

	@Override
	public void componentHidden() {
		tableModel.setProgram(null);
	}

	/**
	 * Build the main panel for this component.
	 */
	private JPanel buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());

		ServiceProvider serviceProvider = plugin.getTool();
		tableModel = new RelocationTableModel(serviceProvider, currentProgram, null);
		tableModel.addTableModelListener(e -> {
			int rowCount = tableModel.getRowCount();
			setSubTitle(rowCount + " rows");
		});

		threadedPanel = new GhidraThreadedTablePanel<>(tableModel);
		table = threadedPanel.getTable();

		GoToService goToService = serviceProvider.getService(GoToService.class);
		table.installNavigation(serviceProvider, goToService.getDefaultNavigatable());

		table.setPreferredScrollableViewportSize(new Dimension(300, 200));
		table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_NEXT_COLUMN);

		table.getSelectionModel().addListSelectionListener(e -> contextChanged());

		ToolTipManager.sharedInstance().registerComponent(table);

		panel.add(threadedPanel, BorderLayout.CENTER);

		tableFilterPanel = new GhidraTableFilterPanel<>(table, tableModel);
		panel.add(tableFilterPanel, BorderLayout.SOUTH);

		return panel;
	}

	void setProgram(Program program) {
		currentProgram = program;
		if (isVisible()) {
			tableModel.setProgram(currentProgram);
		}
	}

	GhidraTable getTable() {
		return table;
	}

	void dispose() {
		setProgram(null);
		removeFromTool();
		threadedPanel.dispose();
		tableFilterPanel.dispose();

	}
}
