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

import java.util.Comparator;
import java.util.Iterator;

import docking.widgets.table.DiscoverableTableUtils;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.app.plugin.core.relocobj.RelocationTableModel.RelocationRowObject;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.relocobj.RelocationEntry;
import ghidra.program.model.relocobj.RelocationGang;
import ghidra.program.model.relocobj.RelocationGangRoleDescriptor;
import ghidra.program.model.relocobj.RelocationGroup;
import ghidra.program.model.relocobj.RelocationTable.RelocationLocation;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.table.field.AddressTableColumn;
import ghidra.util.task.TaskMonitor;

class RelocationTableModel extends AddressBasedTableModel<RelocationRowObject> {
	private static Comparator<RelocationRowObject> ADDRESS_SORT_COMPARATOR =
		new Comparator<RelocationTableModel.RelocationRowObject>() {

			@Override
			public int compare(RelocationRowObject o1, RelocationRowObject o2) {
				int c = o1.address.compareTo(o2.address);
				if (c == 0) {
					c = o1.relocationIndex - o2.relocationIndex;
				}
				return c;
			}
		};

	static final int MEMORY_BLOCK_COL = 0;
	static final int ADDRESS_COL = 1;
	static final int TYPE_COL = 2;
	static final int NAME_COL = 3;
	static final int ADDEND_COL = 4;

	static final String MEMORY_BLOCK = "Memory block";
	static final String RELOCATION_ADDRESS = "Address";
	static final String RELOCATION_TYPE = "Type";
	static final String RELOCATION_NAME = "Symbol name";
	static final String RELOCATION_ADDEND = "Addend";
	static final String TARGET_ADDRESS = "Target address";

	public RelocationTableModel(ServiceProvider serviceProvider, Program program,
			TaskMonitor monitor) {
		super("Relocation Table Model (synthesized)", serviceProvider, program, monitor);
	}

	@Override
	protected TableColumnDescriptor<RelocationRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<RelocationRowObject> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new RelocationMemoryBlockColumn());
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new AddressTableColumn()), 1, true);
		descriptor.addVisibleColumn(new RelocationTypeColumn());
		descriptor.addVisibleColumn(new RelocationNameColumn());
		descriptor.addHiddenColumn(new RelocationTargetColumn());
		descriptor.addVisibleColumn(new RelocationAddendColumn());

		return descriptor;
	}

	@Override
	protected Comparator<RelocationRowObject> createSortComparator(int columnIndex) {
		if (columnIndex == ADDRESS_COL) {
			return ADDRESS_SORT_COMPARATOR;
		}
		return super.createSortComparator(columnIndex);
	}

	@Override
	public void setProgram(Program p) {
		super.setProgram(p);
		reload();
		fireTableDataChanged();
	}

	@Override
	protected void doLoad(Accumulator<RelocationRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		if (getProgram() == null) {
			return;
		}

		int relocationIndex = 0;
		RelocationTable relocationTable = RelocationTable.get(getProgram());
		Iterator<RelocationGroup> groupIterator = relocationTable.getRelocationGroups();
		while (groupIterator.hasNext()) {
			RelocationGroup group = groupIterator.next();
			for (int gangIndex = 0; gangIndex < group.getGangs().size(); gangIndex++) {
				RelocationGang gang = group.getGangs().get(gangIndex);
				String typeName = RelocationGangRoleDescriptor.derive(group, gangIndex).toString();
				for (int entryIndex = 0; entryIndex < gang.getEntries().size(); entryIndex++) {
					RelocationEntry entry = gang.getEntries().get(entryIndex);
					long addend = group.getAddend() + entry.localAddend();
					accumulator.add(new RelocationRowObject(++relocationIndex, entry.address(),
						group, gangIndex, entryIndex, typeName, addend));
				}
			}
		}
	}

	@Override
	public Address getAddress(int row) {
		RelocationRowObject rowObject = filteredData.get(row);
		return rowObject.address;
	}

	//==================================================================================================
	// Inner Classes
	//==================================================================================================    

	static class RelocationRowObject {
		final int relocationIndex;
		final Address address;
		final RelocationGroup group;
		final int gangIndex;
		final int entryIndex;
		final Address target;
		final String relocationTypeName;
		final long addend;

		public RelocationRowObject(int relocationIndex, Address address, RelocationGroup group,
				int gangIndex, int entryIndex, String relocationTypeName, long addend) {
			this.relocationIndex = relocationIndex;
			this.address = address;
			this.group = group;
			this.gangIndex = gangIndex;
			this.entryIndex = entryIndex;
			this.target = group.getTarget();
			this.relocationTypeName = relocationTypeName;
			this.addend = addend;
		}
	}

	private static class RelocationMemoryBlockColumn extends
			AbstractProgramBasedDynamicTableColumn<RelocationRowObject, String> {
		@Override
		public String getColumnName() {
			return MEMORY_BLOCK;
		}

		@Override
		public String getValue(RelocationRowObject rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			MemoryBlock memoryBlock =
				program.getMemory().getBlock(rowObject.address);
			return memoryBlock != null ? memoryBlock.getName() : "(none)";
		}
	}

	private static class RelocationTypeColumn extends
			AbstractProgramBasedDynamicTableColumn<RelocationRowObject, String> {
		@Override
		public String getColumnName() {
			return RELOCATION_TYPE;
		}

		@Override
		public String getValue(RelocationRowObject rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.relocationTypeName;
		}
	}

	private static class RelocationNameColumn extends
			AbstractProgramBasedDynamicTableColumn<RelocationRowObject, String> {
		@Override
		public String getColumnName() {
			return RELOCATION_NAME;
		}

		@Override
		public String getValue(RelocationRowObject rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			Address target = rowObject.target;
			Symbol symbol = program.getSymbolTable().getPrimarySymbol(target);
			return symbol != null ? symbol.getName(true) : "(none)";
		}
	}

	private static class RelocationAddendColumn extends
			AbstractProgramBasedDynamicTableColumn<RelocationRowObject, String> {
		@Override
		public String getColumnName() {
			return RELOCATION_ADDEND;
		}

		@Override
		public String getValue(RelocationRowObject rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			long addend = rowObject.addend;
			return Long.toString(addend);
		}
	}

	private static class RelocationTargetColumn extends
			AbstractProgramBasedDynamicTableColumn<RelocationRowObject, Address> {
		@Override
		public String getColumnName() {
			return TARGET_ADDRESS;
		}

		@Override
		public Address getValue(RelocationRowObject rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.target;
		}
	}
}
