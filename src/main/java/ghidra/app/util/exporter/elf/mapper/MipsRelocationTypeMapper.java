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
import ghidra.app.util.bin.format.elf.relocation.MIPS_ElfRelocationType;
import ghidra.app.util.exporter.elf.ElfRelocatableObject;
import ghidra.app.util.exporter.elf.ElfRelocatableSection;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.relocobj.Relocation;
import ghidra.program.model.relocobj.RelocationAbsolute;
import ghidra.program.model.relocobj.RelocationHighPair;
import ghidra.program.model.relocobj.RelocationLowPair;
import ghidra.program.model.relocobj.RelocationMIPS26;
import ghidra.program.model.relocobj.RelocationRelativePC;
import ghidra.program.model.relocobj.RelocationRelativeSymbol;

public class MipsRelocationTypeMapper implements ElfRelocationTypeMapper {
	@Override
	public int apply(ElfRelocatableSection relSection, Relocation r, MessageLog log) {
		String relSectionName = relSection.getName();

		if (r instanceof RelocationAbsolute) {
			RelocationAbsolute rel = (RelocationAbsolute) r;
			int width = rel.getWidth();
			switch (width) {
				case 4:
					return MIPS_ElfRelocationType.R_MIPS_32.typeId();
				case 8:
					return MIPS_ElfRelocationType.R_MIPS_64.typeId();
				default:
					log.appendMsg(relSectionName, String.format(
						"Unknown RelocationAbsolute width %d at %s", width, r.getAddress()));
					return MIPS_ElfRelocationType.R_MIPS_NONE.typeId();
			}
		}
		else if (r instanceof RelocationHighPair) {
			RelocationHighPair rel = (RelocationHighPair) r;
			long bitfield = rel.getBitmask();

			if (bitfield == 0xffff) {
				return MIPS_ElfRelocationType.R_MIPS_HI16.typeId();
			}
			else {
				log.appendMsg(relSectionName,
					String.format("Unknown RelocationHighPair bitfield 0x%x at %s", bitfield,
						r.getAddress()));
				return MIPS_ElfRelocationType.R_MIPS_NONE.typeId();
			}
		}
		else if (r instanceof RelocationLowPair) {
			RelocationLowPair rel = (RelocationLowPair) r;
			long bitfield = rel.getBitmask();

			if (bitfield == 0xffff) {
				return MIPS_ElfRelocationType.R_MIPS_LO16.typeId();
			}
			else {
				log.appendMsg(relSectionName,
					String.format("Unknown RelocationHighPair bitfield 0x%x at %s", bitfield,
						r.getAddress()));
				return MIPS_ElfRelocationType.R_MIPS_NONE.typeId();
			}
		}
		else if (r instanceof RelocationRelativeSymbol) {
			RelocationRelativeSymbol rel = (RelocationRelativeSymbol) r;
			int width = rel.getWidth();
			long bitfield = rel.getBitmask();
			String symbol = rel.getRelativeSymbolName();

			if (width == 2 && bitfield == 0xffff && symbol.equals("_gp")) {
				return MIPS_ElfRelocationType.R_MIPS_GPREL16.typeId();
			}
			else {
				log.appendMsg(relSectionName,
					String.format(
						"Unknown RelocationRelativeSymbol width %d bitfield 0x%x symbol %s at %s",
						width, bitfield, symbol, r.getAddress()));
				return MIPS_ElfRelocationType.R_MIPS_NONE.typeId();
			}
		}
		else if (r instanceof RelocationRelativePC) {
			RelocationRelativePC rel = (RelocationRelativePC) r;
			int width = rel.getWidth();
			long bitfield = rel.getBitmask();

			if (width == 2 && bitfield == 0xffff) {
				return MIPS_ElfRelocationType.R_MIPS_PC16.typeId();
			}
			else {
				log.appendMsg(relSectionName,
					String.format(
						"Unknown RelocationRelativeSymbol width %d bitfield 0x%x at %s", width,
						bitfield, r.getAddress()));
				return MIPS_ElfRelocationType.R_MIPS_NONE.typeId();
			}
		}
		else if (r instanceof RelocationMIPS26) {
			return MIPS_ElfRelocationType.R_MIPS_26.typeId();
		}
		else {
			log.appendMsg(relSectionName, String.format("Unknown relocation type %s at %s",
				r.getClass().getSimpleName(), r.getAddress()));
			return MIPS_ElfRelocationType.R_MIPS_NONE.typeId();
		}
	}

	public boolean canApply(ElfRelocatableObject object) {
		return object.getElfMachine() == ElfConstants.EM_MIPS;
	}
}
