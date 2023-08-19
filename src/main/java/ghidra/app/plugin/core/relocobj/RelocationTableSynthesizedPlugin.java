/* ###
 * IP: GHIDRA
 *
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

import docking.action.DockingAction;
import ghidra.MiscellaneousPluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.GoToService;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ChangeManager;
import ghidra.util.table.SelectionNavigationAction;
import ghidra.util.table.actions.MakeProgramSelectionAction;

//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.MISC,
	shortDescription = "Manages synthesized relocation information",
	description = "This plugin manages synthesized relocation information, to be used for exporting relocatable object files.",
	servicesRequired = { GoToService.class },
	eventsProduced = { ProgramLocationPluginEvent.class },
	eventsConsumed = { ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class RelocationTableSynthesizedPlugin extends Plugin implements DomainObjectListener {
	private Program currentProgram;
	private RelocationProvider provider;

	public RelocationTableSynthesizedPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		provider = new RelocationProvider(this);
		createActions();
	}

	private void createActions() {
		DockingAction selectAction = new MakeProgramSelectionAction(this, provider.getTable());
		tool.addLocalAction(provider, selectAction);

		DockingAction navigationAction = new SelectionNavigationAction(this, provider.getTable());
		tool.addLocalAction(provider, navigationAction);
	}

	@Override
	public void dispose() {
		super.dispose();
		provider.dispose();
		currentProgram = null;
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent ev = (ProgramActivatedPluginEvent) event;
			Program oldProg = currentProgram;
			Program newProg = ev.getActiveProgram();
			if (oldProg != null) {
				programClosed();
			}
			if (newProg != null) {
				programOpened(newProg);
			}
		}
	}

	private void programOpened(Program p) {
		p.addListener(this);
		currentProgram = p;
		provider.setProgram(p);
	}

	private void programClosed() {
		currentProgram.removeListener(this);
		currentProgram = null;
		provider.setProgram(null);
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (ev.containsEvent(ChangeManager.DOCR_IMAGE_BASE_CHANGED) ||
			ev.containsEvent(ChangeManager.DOCR_RELOCATION_ADDED) ||
			ev.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
			provider.setProgram(currentProgram);
		}
	}
}
