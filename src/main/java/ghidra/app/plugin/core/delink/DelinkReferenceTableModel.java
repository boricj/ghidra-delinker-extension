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

import com.google.common.base.Function;

import docking.widgets.table.DiscoverableTableUtils;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.ProgramLocation;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.ProgramBasedDynamicTableColumnExtensionPoint;
import ghidra.util.table.field.ReferenceFromAddressTableColumn;
import ghidra.util.table.field.ReferenceFromLabelTableColumn;
import ghidra.util.table.field.ReferenceToAddressTableColumn;
import ghidra.util.table.field.ReferenceToLabelTableColumn;
import ghidra.util.task.TaskMonitor;

class DelinkReferenceTableModel extends AddressBasedTableModel<Reference> {
	private DelinkObjectProvider provider;
	private PluginTool tool;
	private Program program;

	DelinkReferenceTableModel(DelinkObjectProvider provider, PluginTool tool, Program program) {
		super("References", tool, program, null);
		this.provider = provider;
		this.tool = tool;
		this.program = program;
	}

	@Override
	protected TableColumnDescriptor<Reference> createTableColumnDescriptor() {
		TableColumnDescriptor<Reference> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new ReferenceFromAddressTableColumn()),
			1, true);
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new ReferenceFromLabelTableColumn()));
		descriptor
				.addVisibleColumn(new SectionTableColumn("From section", r -> r.getFromAddress()));
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new ReferenceToAddressTableColumn()),
			1, true);
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new ReferenceToLabelTableColumn()));
		descriptor.addVisibleColumn(new SectionTableColumn("To section", r -> r.getToAddress()));

		return descriptor;
	}

	@Override
	protected void doLoad(Accumulator<Reference> accumulator, TaskMonitor monitor)
			throws CancelledException {
		DelinkObjectModel model = provider.getModel();

		monitor.initialize(model.getAllReferencesAsStream().count());
		int value = 0;

		Iterator<Reference> it = model.getAllReferencesAsStream().iterator();
		while (it.hasNext()) {
			monitor.setProgress(value++);
			monitor.checkCanceled();
			Reference r = it.next();
			accumulator.add(r);
		}
	}

	@Override
	public Address getAddress(int row) {
		Reference rowObject = getRowObject(row);
		if (rowObject == null) {
			return null;
		}
		return rowObject.getFromAddress();
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int column) {
		return new ProgramLocation(program, (Address) getValueAt(row, 0));
	}

	//==================================================================================================
	// Table Column Classes
	//==================================================================================================

	private class SectionTableColumn
			extends ProgramBasedDynamicTableColumnExtensionPoint<Reference, String> {
		private final String columnName;
		private final Function<Reference, Address> addressExtractor;

		public SectionTableColumn(String columnName,
				Function<Reference, Address> addressExtractor) {
			this.columnName = columnName;
			this.addressExtractor = addressExtractor;
		}

		@Override
		public String getColumnName() {
			return columnName;
		}

		@Override
		public String getValue(Reference rowObject, Settings settings, Program data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			Address address = addressExtractor.apply(rowObject);

			DelinkObjectModel model = provider.getModel();
			for (DelinkSectionModel section : model.getSections()) {
				if (section.getAddressSetView().contains(address)) {
					return section.getName();
				}
			}

			return "External";
		}
	}
}
