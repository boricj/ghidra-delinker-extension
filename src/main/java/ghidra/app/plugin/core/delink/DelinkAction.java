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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.core.programtree.ProgramNode;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Group;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;

public abstract class DelinkAction extends DockingAction {
	protected DelinkPlugin plugin;

	public DelinkAction(DelinkPlugin plugin, String name, String owner, String[] menuPath) {
		super(name, owner);
		this.plugin = plugin;

		setPopupMenuData(new MenuData(menuPath, null, "module"));
		setDescription(name);
		setEnabled(true);
	}

	public abstract AddressSetView createDelinkTargetFromActionContext(ActionContext context);

	@Override
	public void actionPerformed(ActionContext context) {
		DelinkObjectModel objectModel = createDelinkObjectModelFromActionContext(context);
		objectModel.delink();
		plugin.displayProvider(objectModel);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		DelinkObjectModel objectModel = createDelinkObjectModelFromActionContext(context);

		return objectModel != null;
	}

	private static List<ProgramFragment> getAllFragmentsFromGroup(Group group) {
		if (group instanceof ProgramFragment) {
			return Arrays.asList((ProgramFragment) group);
		}
		else if (group instanceof ProgramModule) {
			ProgramModule module = (ProgramModule) group;

			List<ProgramFragment> fragments = new ArrayList<>();
			for (Group child : module.getChildren()) {
				fragments.addAll(getAllFragmentsFromGroup(child));
			}

			return fragments;
		}

		return Collections.<ProgramFragment> emptyList();
	}

	public DelinkObjectModel createDelinkObjectModelFromActionContext(ActionContext context) {
		AddressSetView target = createDelinkTargetFromActionContext(context);
		if (target == null) {
			return null;
		}

		Object activeObj = context.getContextObject();

		if (activeObj == null || !(activeObj instanceof ProgramNode)) {
			return null;
		}

		ProgramNode node = (ProgramNode) activeObj;
		Program program = node.getProgram();
		List<ProgramFragment> fragments = getAllFragmentsFromGroup(node.getGroup());
		if (node.getTree().getSelectionCount() != 1 || program == null || fragments.isEmpty()) {
			return null;
		}

		DelinkObjectModel object = new DelinkObjectModel(program, node.getName(), target);

		for (ProgramFragment fragment : fragments) {
			object.addSection(fragment.getName(), fragment);
		}

		return object;
	}
}
