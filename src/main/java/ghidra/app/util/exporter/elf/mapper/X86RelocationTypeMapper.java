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
package ghidra.app.util.exporter.elf.mapper;

import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.relocation.X86_32_ElfRelocationType;
import ghidra.app.util.exporter.elf.ElfRelocatableObject;
import ghidra.app.util.exporter.elf.ElfRelocatableSection;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.relocobj.Relocation;
import ghidra.program.model.relocobj.RelocationAbsolute;
import ghidra.program.model.relocobj.RelocationRelativePC;

public class X86RelocationTypeMapper implements ElfRelocationTypeMapper {
	@Override
	public int apply(ElfRelocatableSection relSection, Relocation r, MessageLog log) {
		String relSectionName = relSection.getName();

		if (r instanceof RelocationAbsolute) {
			RelocationAbsolute rel = (RelocationAbsolute) r;
			int width = rel.getWidth();
			switch (width) {
				case 4:
					return X86_32_ElfRelocationType.R_386_32.typeId();
				default:
					log.appendMsg(relSectionName, String.format(
						"Unknown RelocationAbsolute width %d at %s", width, r.getAddress()));
					return X86_32_ElfRelocationType.R_386_NONE.typeId();
			}
		}
		else if (r instanceof RelocationRelativePC) {
			RelocationRelativePC rel = (RelocationRelativePC) r;
			int width = rel.getWidth();
			switch (width) {
				case 4:
					return X86_32_ElfRelocationType.R_386_PC32.typeId();
				default:
					log.appendMsg(relSectionName, String.format(
						"Unknown RelocationRelative width %d at %s", width, r.getAddress()));
					return X86_32_ElfRelocationType.R_386_NONE.typeId();
			}
		}
		else {
			log.appendMsg(relSectionName, String.format("Unknown relocation type %s at %s",
				r.getClass().getSimpleName(), r.getAddress()));
			return X86_32_ElfRelocationType.R_386_NONE.typeId();
		}
	}

	public boolean canApply(ElfRelocatableObject object) {
		return object.getElfMachine() == ElfConstants.EM_386 &&
			object.getElfClass() == ElfConstants.ELF_CLASS_32;
	}
}
