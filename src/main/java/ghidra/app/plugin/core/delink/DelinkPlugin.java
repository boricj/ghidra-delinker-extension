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
import java.util.List;

import docking.ActionContext;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.programtree.ProgramNode;
import ghidra.app.services.ProgramTreeService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

/**
 * Plugin for reversing the work of a linker by identifying references and
 * symbols crossing a program subset.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.MISC,
	shortDescription = "Plugin for listing symbols and references of a subset of a program",
	description = "Plugin for reversing the work of a linker by identifying " +
		"references and symbols crossing a program subset.",
	servicesRequired = { ProgramTreeService.class }
)
//@formatter:on
public class DelinkPlugin extends ProgramPlugin {
	private final static String[] DELINK_AGAINST_WHOLE_PROGRAM =
		new String[] { "Delink Against", "Whole Program" };
	private final static String[] DELINK_AGAINST_CURRENT_PROGRAM_VIEW =
		new String[] { "Delink Against", "Current Program View" };

	private DelinkAction delinkSelectedProgramNodeAgainstWholeProgram;
	private DelinkAction delinkSelectedProgramNodeAgainstCurrentView;

	private List<DelinkObjectProvider> providerList = new ArrayList<>();

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public DelinkPlugin(PluginTool tool) {
		super(tool);

		createActions();
	}

	private void createActions() {
		delinkSelectedProgramNodeAgainstWholeProgram = new DelinkAction(
			this,
			"Delink selected program node against whole program",
			getName(),
			DELINK_AGAINST_WHOLE_PROGRAM) {
			@Override
			public AddressSetView createDelinkTargetFromActionContext(ActionContext context) {
				Object activeObj = context.getContextObject();

				if (activeObj == null || !(activeObj instanceof ProgramNode)) {
					return null;
				}

				ProgramNode node = (ProgramNode) activeObj;
				Program program = node.getProgram();
				if (program == null) {
					return null;
				}

				AddressFactory addressFactory = program.getAddressFactory();
				Address minAddress = program.getMinAddress();
				Address maxAddress = program.getMaxAddress();

				if (minAddress == null || maxAddress == null) {
					return null;
				}

				return addressFactory.getAddressSet(minAddress, maxAddress);
			}
		};

		delinkSelectedProgramNodeAgainstCurrentView = new DelinkAction(
			this,
			"Delink selected program node against current program view",
			getName(),
			DELINK_AGAINST_CURRENT_PROGRAM_VIEW) {
			@Override
			public AddressSetView createDelinkTargetFromActionContext(ActionContext context) {
				return plugin.getTool().getService(ProgramTreeService.class).getView();
			}
		};

		tool.addAction(delinkSelectedProgramNodeAgainstWholeProgram);
		tool.addAction(delinkSelectedProgramNodeAgainstCurrentView);
	}

	public void displayProvider(DelinkObjectModel model) {
		DelinkObjectProvider provider = findProvider(model);
		if (provider == null) {
			provider = new DelinkObjectProvider(this, model);
		}
		else {
			provider.update();
		}

		tool.showComponentProvider(provider, true);
	}

	private DelinkObjectProvider findProvider(DelinkObjectModel model) {
		for (DelinkObjectProvider provider : providerList) {
			if (provider.equals(model)) {
				return provider;
			}
		}

		return null;
	}

	public void providerDismissed(DelinkObjectProvider provider) {
		providerList.remove(provider);

		provider.dispose();
	}
}
