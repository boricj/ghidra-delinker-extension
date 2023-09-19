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

import java.util.Iterator;
import java.util.stream.Stream;

import docking.widgets.table.DiscoverableTableUtils;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.app.plugin.core.symtable.SymbolRowObject;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramLocation;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.table.field.AddressTableColumn;
import ghidra.util.table.field.ProgramBasedDynamicTableColumnExtensionPoint;
import ghidra.util.task.TaskMonitor;

class DelinkSymbolTableModel extends AddressBasedTableModel<SymbolRowObject> {
	private static final int LABEL_COL = 0;
	private static final int LOCATION_COL = 1;
	private static final int SECTION_COL = 2;

	private DelinkObjectProvider provider;
	private PluginTool tool;

	DelinkSymbolTableModel(DelinkObjectProvider provider, PluginTool tool) {
		super("Symbols", tool, null, null);
		this.provider = provider;
		this.tool = tool;
	}

	@Override
	protected TableColumnDescriptor<SymbolRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<SymbolRowObject> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new NameTableColumn());
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new AddressTableColumn()), 1, true);
		descriptor.addVisibleColumn(new SectionTableColumn());

		return descriptor;
	}

	@Override
	protected void doLoad(Accumulator<SymbolRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		monitor.initialize(getKeyCount());
		int value = 0;

		DelinkObjectModel model = provider.getModel();
		Iterator<Symbol> it =
			Stream.concat(model.getExternalSymbols().stream(), model.getInternalSymbols().stream())
					.iterator();

		while (it.hasNext()) {
			monitor.setProgress(value++);
			monitor.checkCanceled();
			Symbol s = it.next();
			accumulator.add(new SymbolRowObject(s));
		}
	}

	@Override
	public Address getAddress(int row) {
		SymbolRowObject rowObject = getRowObject(row);
		if (rowObject == null) {
			return null;
		}
		Symbol symbol = rowObject.getSymbol();
		if (symbol == null || symbol.isDeleted()) {
			return null;
		}
		return symbol.getAddress();
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int column) {
		Symbol s = (Symbol) getValueAt(row, LABEL_COL);
		if (s == null || s.isDeleted()) {
			return null;
		}
		return s.getProgramLocation();
	}

	private int getKeyCount() {
		DelinkObjectModel model = provider.getModel();
		return model.getExternalSymbols().size() + model.getInternalSymbols().size();
	}

	//==================================================================================================
	// Table Column Classes
	//==================================================================================================

	private class NameTableColumn
			extends AbstractProgramBasedDynamicTableColumn<SymbolRowObject, Symbol> {

		@Override
		public String getColumnName() {
			return "Name";
		}

		@Override
		public Symbol getValue(SymbolRowObject rowObject, Settings settings, Program p,
				ServiceProvider svcProvider) throws IllegalArgumentException {
			return rowObject.getSymbol();
		}
	}

	public class SectionTableColumn
			extends ProgramBasedDynamicTableColumnExtensionPoint<SymbolRowObject, String> {

		@Override
		public String getColumnName() {
			return "Section";
		}

		@Override
		public String getValue(SymbolRowObject rowObject, Settings settings, Program data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			Symbol symbol = rowObject.getSymbol();
			if (symbol == null || symbol.isDeleted()) {
				return null;
			}

			DelinkObjectModel model = provider.getModel();
			if (model.getExternalSymbols().contains(symbol)) {
				return "External";
			}

			for (DelinkSectionModel section : model.getSections()) {
				if (section.getInternalSymbols().contains(symbol)) {
					return section.getName();
				}
			}

			return null;
		}
	}
}
