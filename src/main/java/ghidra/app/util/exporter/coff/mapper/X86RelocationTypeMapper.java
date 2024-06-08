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
package ghidra.app.util.exporter.coff.mapper;

import ghidra.app.util.bin.format.coff.CoffMachineType;
import ghidra.app.util.bin.format.coff.relocation.X86_32_CoffRelocationHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.relocobj.Relocation;
import ghidra.program.model.relocobj.RelocationAbsolute;
import ghidra.program.model.relocobj.RelocationRelativePC;

public class X86RelocationTypeMapper implements CoffRelocationTypeMapper {
	@Override
	public short apply(Relocation r, MessageLog log) {
		if (r instanceof RelocationAbsolute rel) {
			int width = rel.getWidth();
			switch (width) {
				case 4:
					return X86_32_CoffRelocationHandler.IMAGE_REL_I386_DIR32;
				default:
					log.appendMsg(String.format(
						"Unknown RelocationAbsolute width %d at %s", width, r.getAddress()));
					return X86_32_CoffRelocationHandler.IMAGE_REL_I386_ABSOLUTE;
			}
		}
		else if (r instanceof RelocationRelativePC) {
			RelocationRelativePC rel = (RelocationRelativePC) r;
			int width = rel.getWidth();
			switch (width) {
				case 4:
					return X86_32_CoffRelocationHandler.IMAGE_REL_I386_REL32;
				default:
					log.appendMsg(String.format(
						"Unknown RelocationRelative width %d at %s", width, r.getAddress()));
					return X86_32_CoffRelocationHandler.IMAGE_REL_I386_ABSOLUTE;
			}
		}
		else {
			log.appendMsg(String.format("Unknown relocation type %s at %s",
				r.getClass().getSimpleName(), r.getAddress()));
			return X86_32_CoffRelocationHandler.IMAGE_REL_I386_ABSOLUTE;
		}
	}

	@Override
	public boolean canApply(int machine) {
		return machine == CoffMachineType.IMAGE_FILE_MACHINE_I386;
	}
}
