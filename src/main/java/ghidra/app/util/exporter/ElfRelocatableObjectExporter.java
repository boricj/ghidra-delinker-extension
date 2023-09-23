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
package ghidra.app.util.exporter;

import java.awt.Component;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.stream.Collectors;

import javax.swing.JComboBox;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.exporter.elf.ElfRelocatableObject;
import ghidra.app.util.exporter.elf.ElfRelocatableSection;
import ghidra.app.util.exporter.elf.ElfRelocatableSectionNoBits;
import ghidra.app.util.exporter.elf.ElfRelocatableSectionProgBits;
import ghidra.app.util.exporter.elf.ElfRelocatableSectionRelTable;
import ghidra.app.util.exporter.elf.ElfRelocatableSectionRelaTable;
import ghidra.app.util.exporter.elf.ElfRelocatableSectionStringTable;
import ghidra.app.util.exporter.elf.ElfRelocatableSectionSymbolTable;
import ghidra.app.util.exporter.elf.ElfRelocatableSymbol;
import ghidra.app.util.exporter.elf.mapper.ElfRelocationTypeMapper;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.relocobj.Relocation;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;

/**
 * An implementation of exporter that creates an ELF relocatable object from the
 * program.
 */
public class ElfRelocatableObjectExporter extends Exporter {
	private short e_ident_machine;
	private byte e_ident_class;
	private byte e_ident_data;
	private boolean generateStringAndSymbolTables;
	private boolean includeDynamicSymbols;
	private boolean generateRelocationTables;
	private boolean generateSectionNamesStringTable;
	private int relocationTableFormat;

	private ElfRelocatableObject elf;
	private ElfRelocatableSectionStringTable strtab;
	private ElfRelocatableSectionSymbolTable symtab;
	private ElfRelocatableSectionStringTable shstrtab;

	private Program program;
	private AddressSetView programSet;
	private AddressSetView fileSet;

	private Map<String, ElfRelocatableSymbol> symbolsByName;
	private List<Section> sections = new ArrayList<>();

	private static final Map<Byte, String> ELF_CLASSES = new TreeMap<>(Map.ofEntries(
		Map.entry(ElfConstants.ELF_CLASS_NONE, "(none)"),
		Map.entry(ElfConstants.ELF_CLASS_32, "32 bits"),
		Map.entry(ElfConstants.ELF_CLASS_64, "64 bits")));

	private static final Map<Byte, String> ELF_DATAS = new TreeMap<>(Map.ofEntries(
		Map.entry(ElfConstants.ELF_DATA_NONE, "(none)"),
		Map.entry(ElfConstants.ELF_DATA_LE, "Little endian"),
		Map.entry(ElfConstants.ELF_DATA_BE, "Big endian")));

	private static final Map<Short, String> ELF_MACHINES = new TreeMap<>(Map.ofEntries(
		Map.entry(ElfConstants.EM_NONE, "(none)"),
		Map.entry(ElfConstants.EM_386, "i386"),
		Map.entry(ElfConstants.EM_X86_64, "x86_64"),
		Map.entry(ElfConstants.EM_ARM, "ARM"),
		Map.entry(ElfConstants.EM_AARCH64, "AARCH64"),
		Map.entry(ElfConstants.EM_PPC, "PowerPC"),
		Map.entry(ElfConstants.EM_PPC64, "PowerPC64"),
		Map.entry(ElfConstants.EM_SPARC, "SPARC"),
		Map.entry(ElfConstants.EM_SPARCV9, "SPARC V9"),
		Map.entry(ElfConstants.EM_RISCV, "RISC-V"),
		Map.entry(ElfConstants.EM_MIPS, "MIPS"),
		Map.entry(ElfConstants.EM_SH, "SuperH"),
		Map.entry(ElfConstants.EM_68K, "68000")));

	private static final Map<Integer, String> ELF_RELOCATION_TABLE_TYPES =
		new TreeMap<>(Map.ofEntries(
			Map.entry(ElfSectionHeaderConstants.SHT_NULL, "(none)"),
			Map.entry(ElfSectionHeaderConstants.SHT_REL, "REL"),
			Map.entry(ElfSectionHeaderConstants.SHT_RELA, "RELA"),
			Map.entry(ElfSectionHeaderConstants.SHT_RELR, "RELR"),
			Map.entry(ElfSectionHeaderConstants.SHT_ANDROID_REL, "ANDROID_REL"),
			Map.entry(ElfSectionHeaderConstants.SHT_ANDROID_RELA, "ANDROID_RELA"),
			Map.entry(ElfSectionHeaderConstants.SHT_ANDROID_RELR, "ANDROID_RELR")));

	private static final class ProcessorInfo {
		String processor;
		int pointerSize;

		public ProcessorInfo(String processor, int pointerSize) {
			this.processor = processor;
			this.pointerSize = pointerSize;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof ProcessorInfo)) {
				return false;
			}

			ProcessorInfo info = (ProcessorInfo) obj;
			return processor.equals(info.processor) && pointerSize == info.pointerSize;
		}

		@Override
		public int hashCode() {
			return Objects.hash(processor, pointerSize);
		}
	};

	private static final Map<ProcessorInfo, Short> GHIDRA_TO_ELF_MACHINES = Map.ofEntries(
		Map.entry(new ProcessorInfo("x86", 4), ElfConstants.EM_386),
		Map.entry(new ProcessorInfo("x86", 8), ElfConstants.EM_X86_64),
		Map.entry(new ProcessorInfo("ARM", 4), ElfConstants.EM_ARM),
		Map.entry(new ProcessorInfo("AARCH64", 8), ElfConstants.EM_AARCH64),
		Map.entry(new ProcessorInfo("PowerPC", 4), ElfConstants.EM_PPC),
		Map.entry(new ProcessorInfo("PowerPC", 8), ElfConstants.EM_PPC64),
		Map.entry(new ProcessorInfo("68000", 4), ElfConstants.EM_68K),
		Map.entry(new ProcessorInfo("Sparc", 4), ElfConstants.EM_SPARC),
		Map.entry(new ProcessorInfo("Sparc", 8), ElfConstants.EM_SPARCV9),
		Map.entry(new ProcessorInfo("SuperH", 4), ElfConstants.EM_SH),
		Map.entry(new ProcessorInfo("MIPS", 4), ElfConstants.EM_MIPS),
		Map.entry(new ProcessorInfo("MIPS", 8), ElfConstants.EM_MIPS),
		Map.entry(new ProcessorInfo("PSX", 4), ElfConstants.EM_MIPS),
		Map.entry(new ProcessorInfo("RISCV", 4), ElfConstants.EM_RISCV));

	private static final Map<ProcessorInfo, Integer> GHIDRA_TO_ELF_RELOCATION_TYPES = Map.ofEntries(
		Map.entry(new ProcessorInfo("x86", 4), ElfSectionHeaderConstants.SHT_REL),
		Map.entry(new ProcessorInfo("x86", 8), ElfSectionHeaderConstants.SHT_RELA),
		Map.entry(new ProcessorInfo("ARM", 4), ElfSectionHeaderConstants.SHT_REL),
		Map.entry(new ProcessorInfo("AARCH64", 8), ElfSectionHeaderConstants.SHT_RELA),
		Map.entry(new ProcessorInfo("PowerPC", 4), ElfSectionHeaderConstants.SHT_RELA),
		Map.entry(new ProcessorInfo("PowerPC", 8), ElfSectionHeaderConstants.SHT_RELA),
		Map.entry(new ProcessorInfo("68000", 4), ElfSectionHeaderConstants.SHT_RELA),
		Map.entry(new ProcessorInfo("Sparc", 4), ElfSectionHeaderConstants.SHT_RELA),
		Map.entry(new ProcessorInfo("Sparc", 8), ElfSectionHeaderConstants.SHT_RELA),
		Map.entry(new ProcessorInfo("SuperH", 4), ElfSectionHeaderConstants.SHT_RELA),
		Map.entry(new ProcessorInfo("MIPS", 4), ElfSectionHeaderConstants.SHT_REL),
		Map.entry(new ProcessorInfo("MIPS", 8), ElfSectionHeaderConstants.SHT_REL),
		Map.entry(new ProcessorInfo("PSX", 4), ElfSectionHeaderConstants.SHT_REL),
		Map.entry(new ProcessorInfo("RISCV", 4), ElfSectionHeaderConstants.SHT_RELA));

	private static short autodetectElfMachine(Program program) {
		String processor = program.getLanguage().getProcessor().toString();
		int pointerSize = program.getDefaultPointerSize();
		ProcessorInfo info = new ProcessorInfo(processor, pointerSize);

		for (Map.Entry<ProcessorInfo, Short> entry : GHIDRA_TO_ELF_MACHINES.entrySet()) {
			if (info.equals(entry.getKey())) {
				return entry.getValue();
			}
		}

		return ElfConstants.EM_NONE;
	}

	private static byte autodetectElfClass(Program program) {
		if (program.getDefaultPointerSize() == 4) {
			return ElfConstants.ELF_CLASS_32;
		}
		else if (program.getDefaultPointerSize() == 8) {
			return ElfConstants.ELF_CLASS_64;
		}

		return ElfConstants.ELF_CLASS_NONE;
	}

	private static byte autodetectElfData(Program program) {
		if (program.getLanguage().getLanguageDescription().getEndian() == Endian.LITTLE) {
			return ElfConstants.ELF_DATA_LE;
		}
		else if (program.getLanguage().getLanguageDescription().getEndian() == Endian.BIG) {
			return ElfConstants.ELF_DATA_BE;
		}

		return ElfConstants.ELF_DATA_NONE;
	}

	private static int autodetectElfRelocationTableFormat(Program program) {
		String processor = program.getLanguage().getProcessor().toString();
		int pointerSize = program.getDefaultPointerSize();
		ProcessorInfo info = new ProcessorInfo(processor, pointerSize);

		for (Map.Entry<ProcessorInfo, Integer> entry : GHIDRA_TO_ELF_RELOCATION_TYPES.entrySet()) {
			if (info.equals(entry.getKey())) {
				return entry.getValue();
			}
		}

		return ElfSectionHeaderConstants.SHT_NULL;
	}

	private static ElfRelocationTypeMapper findRelocationTypeMapperFor(
			ElfRelocatableSection section, MessageLog log) {
		List<ElfRelocationTypeMapper> mappers =
			ClassSearcher.getInstances(ElfRelocationTypeMapper.class)
					.stream()
					.filter(s -> s.canApply(section.getElfRelocatableObject()))
					.collect(Collectors.toList());

		if (mappers.isEmpty()) {
			log.appendMsg(section.getName(), "No applicable ELF relocation type mappers found");
			return null;
		}

		ElfRelocationTypeMapper mapper = mappers.get(0);
		if (mappers.size() > 1) {
			log.appendMsg(section.getName(),
				String.format("Multiple applicable ELF relocation type mappers found, using %s",
					mapper.getClass().getName()));
		}

		return mapper;
	}

	public ElfRelocatableObjectExporter() {
		super("ELF relocatable object", "o", null);
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		Program program = getProgram(domainObjectService.getDomainObject());
		if (program == null) {
			return EMPTY_OPTIONS;
		}

		Option[] options = new Option[] {
			new DropDownOption<Short>("ELF header", "ELF machine", ELF_MACHINES, Short.class,
				autodetectElfMachine(program)),
			new DropDownOption<Byte>("ELF header", "ELF class", ELF_CLASSES, Byte.class,
				autodetectElfClass(program)),
			new DropDownOption<Byte>("ELF header", "ELF data", ELF_DATAS, Byte.class,
				autodetectElfData(program)),
			new Option("ELF header", "Generate section names string table", true),
			new Option("Symbols", "Generate string & symbol tables", true),
			new Option("Symbols", "Include dynamic symbols", false),
			new Option("Relocations", "Generate relocation tables", true),
			new DropDownOption<Integer>("Relocations", "Relocation table format",
				ELF_RELOCATION_TABLE_TYPES, Integer.class,
				autodetectElfRelocationTableFormat(program))
		};

		return Arrays.asList(options);
	}

	@Override
	public void setOptions(List<Option> options) {
		e_ident_machine = (Short) options.get(0).getValue();
		e_ident_class = (Byte) options.get(1).getValue();
		e_ident_data = (Byte) options.get(2).getValue();
		generateSectionNamesStringTable = (Boolean) options.get(3).getValue();
		generateStringAndSymbolTables = (Boolean) options.get(4).getValue();
		includeDynamicSymbols = (Boolean) options.get(5).getValue();
		generateRelocationTables = (Boolean) options.get(6).getValue();
		relocationTableFormat = (Integer) options.get(7).getValue();
	}

	private class DropDownOption<T> extends Option {
		private final Map<T, String> values;
		private final Map<String, T> reverseValues = new HashMap<>();
		private final Class<T> class_;
		private final T defaultValue;
		private final JComboBox<String> comp;

		public DropDownOption(String group, String name, Map<T, String> values, Class<T> class_,
				T defaultValue) {
			super(group, name, defaultValue);

			this.values = values;
			for (Map.Entry<T, String> entry : values.entrySet()) {
				this.reverseValues.put(entry.getValue(), entry.getKey());
			}

			this.defaultValue = defaultValue;
			this.class_ = class_;

			this.comp = new JComboBox<String>(values.values().toArray(new String[values.size()]));
			this.comp.setSelectedItem(values.get(defaultValue));
		}

		@Override
		public Component getCustomEditorComponent() {
			return comp;
		}

		@Override
		public Option copy() {
			return new DropDownOption<T>(getGroup(), getName(), values, class_, defaultValue);
		}

		@Override
		public T getValue() {
			return reverseValues.get(comp.getSelectedItem());
		}

		@Override
		public Class<?> getValueClass() {
			return class_;
		}
	}

	private class Section {
		private final MemoryBlock memoryBlock;
		private final String name;
		private final AddressSetView addressSet;

		private ElfRelocatableSection section;
		private ElfRelocatableSection relSection;

		public Section(MemoryBlock memoryBlock, AddressSetView addressSet) {
			this.memoryBlock = memoryBlock;
			this.name = memoryBlock.getName();
			this.addressSet = addressSet;
		}

		public String getName() {
			return name;
		}

		public void createElfSection(RelocationTable relocationTable, boolean encodeAddend)
				throws MemoryAccessException {
			if (section != null) {
				throw new IllegalStateException();
			}

			long flags = ElfSectionHeaderConstants.SHF_ALLOC;
			flags |= memoryBlock.isWrite() ? ElfSectionHeaderConstants.SHF_WRITE : 0;
			flags |= memoryBlock.isExecute() ? ElfSectionHeaderConstants.SHF_EXECINSTR : 0;

			if (memoryBlock.isInitialized()) {
				byte[] bytes =
					relocationTable.getOriginalBytes(addressSet, elf.getDataConverter(),
						encodeAddend);
				section = new ElfRelocatableSectionProgBits(elf, name, bytes, flags);
			}
			else {
				long length = addressSet.getNumAddresses();
				section = new ElfRelocatableSectionNoBits(elf, name, length, flags);
			}
		}

		public void addSymbols() {
			symtab.addSectionSymbol(section);

			for (Symbol symbol : program.getSymbolTable().getAllSymbols(includeDynamicSymbols)) {
				if (symbol.isPrimary() && addressSet.contains(symbol.getAddress())) {
					String symbolName = symbol.getName(true);
					byte type = ElfSymbol.STT_NOTYPE;
					byte visibility =
						symbol.isGlobal() ? ElfSymbol.STB_GLOBAL : ElfSymbol.STB_LOCAL;
					long offset =
						Relocation.getAddressOffsetWithinSet(addressSet, symbol.getAddress());
					long size = 0;

					Object obj = symbol.getObject();
					if (obj instanceof CodeUnit) {
						CodeUnit codeUnit = (CodeUnit) obj;

						type = ElfSymbol.STT_OBJECT;
						size = codeUnit.getLength();
					}
					else if (obj instanceof Function) {
						Function function = (Function) obj;

						type = ElfSymbol.STT_FUNC;
						size = (int) function.getBody().getNumAddresses();
					}

					symbolsByName.put(symbolName, symtab.addDefinedSymbol(section, symbolName,
						visibility, type, size, offset));
				}
			}
		}

		public void createElfRelocationTableSection(RelocationTable relocationTable)
				throws MemoryAccessException {
			if (relSection != null) {
				throw new IllegalStateException();
			}

			List<Relocation> relocations = new ArrayList<>();
			relocationTable.getRelocations(addressSet).forEachRemaining(relocations::add);

			if (relocations.isEmpty()) {
				return;
			}

			if (relocationTableFormat == ElfSectionHeaderConstants.SHT_REL) {
				ElfRelocationTypeMapper relocationTypeMapper =
					findRelocationTypeMapperFor(section, log);
				if (relocationTypeMapper == null) {
					return;
				}

				String relName = String.format(".rel%s%s", (name.startsWith(".") ? "" : "."), name);
				ElfRelocatableSectionRelTable table =
					new ElfRelocatableSectionRelTable(elf, relName, symtab, section);

				for (Relocation relocation : relocations) {
					long offset =
						Relocation.getAddressOffsetWithinSet(addressSet, relocation.getAddress());
					long type = relocationTypeMapper.apply(table, relocation, log);
					long symindex = symtab.indexOf(symbolsByName.get(relocation.getSymbolName()));

					table.add(offset, type, symindex);
				}

				relSection = table;
			}
			else if (relocationTableFormat == ElfSectionHeaderConstants.SHT_RELA) {
				ElfRelocationTypeMapper relocationTypeMapper =
					findRelocationTypeMapperFor(section, log);
				if (relocationTypeMapper == null) {
					return;
				}

				String relName =
					String.format(".rela%s%s", (name.startsWith(".") ? "" : "."), name);
				ElfRelocatableSectionRelaTable table =
					new ElfRelocatableSectionRelaTable(elf, relName, symtab, section);

				for (Relocation relocation : relocations) {
					long offset =
						Relocation.getAddressOffsetWithinSet(addressSet, relocation.getAddress());
					long type = relocationTypeMapper.apply(table, relocation, log);
					long symindex = symtab.indexOf(symbolsByName.get(relocation.getSymbolName()));
					long addend = relocation.getAddend();

					table.add(offset, type, symindex, addend);
				}

				relSection = table;
			}
			else if (relocationTableFormat == ElfSectionHeaderConstants.SHT_NULL) {
				log.appendMsg(name,
					"Relocation table format not specified, skipping relocation table generation");
				return;
			}
			else {
				log.appendMsg(name, String.format(
					"Unsupported relocation table format %d, skipping relocation table generation",
					relocationTableFormat));
				return;
			}
		}
	}

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView fileSet,
			TaskMonitor taskMonitor) throws IOException, ExporterException {
		program = getProgram(domainObj);
		if (program == null) {
			return false;
		}
		RelocationTable relocationTable = RelocationTable.get(program);
		Memory memory = program.getMemory();
		if (fileSet == null) {
			fileSet = memory;
		}

		// FIXME: Expose program address set.
		this.programSet = memory;
		this.fileSet = fileSet;

		try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
			elf = new ElfRelocatableObject.Builder(file.getName())
					.setType(ElfConstants.ET_REL)
					.setMachine(e_ident_machine)
					.setClass(e_ident_class)
					.setData(e_ident_data)
					.build();

			if (generateStringAndSymbolTables) {
				addStringAndSymbolTables();
			}

			for (MemoryBlock memoryBlock : program.getMemory().getBlocks()) {
				addSectionForMemoryBlock(memoryBlock);
			}

			for (Section section : sections) {
				taskMonitor.setMessage(String.format("Creating section %s...", section.getName()));
				section.createElfSection(relocationTable, generateRelocationTables);
			}

			if (generateStringAndSymbolTables) {
				taskMonitor.setMessage("Generating symbol table...");

				for (Section section : sections) {
					section.addSymbols();
				}

				computeExternalSymbols(relocationTable);

				if (generateRelocationTables) {
					for (Section section : sections) {
						taskMonitor.setMessage(String.format(
							"Creating relocation table for section %s...", section.getName()));
						section.createElfRelocationTableSection(relocationTable);
					}
				}
			}

			if (generateSectionNamesStringTable) {
				taskMonitor.setMessage("Generating section names string table...");
				addSectionNameStringTable();
			}

			taskMonitor.setMessage("Writing out ELF relocatable object file...");
			writeOutFile(raf);
		}
		catch (MemoryAccessException e) {
			throw new ExporterException(e);
		}

		return true;
	}

	public static Program getProgram(DomainObject domainObj) {
		if (!(domainObj instanceof Program)) {
			return null;
		}
		return (Program) domainObj;
	}

	private void addStringAndSymbolTables() {
		strtab = new ElfRelocatableSectionStringTable(elf, ElfSectionHeaderConstants.dot_strtab);
		symtab =
			new ElfRelocatableSectionSymbolTable(elf, ElfSectionHeaderConstants.dot_symtab, strtab);
		symtab.addFileSymbol(elf.getFileName());

		symbolsByName = new HashMap<>();
	}

	private void addSectionForMemoryBlock(MemoryBlock memoryBlock) {
		AddressSet memoryBlockSet =
			new AddressSet(memoryBlock.getStart(), memoryBlock.getEnd()).intersect(fileSet);

		if (!memoryBlockSet.isEmpty()) {
			sections.add(new Section(memoryBlock, memoryBlockSet));
		}
	}

	private void computeExternalSymbols(RelocationTable relocationTable) {
		for (Relocation relocation : (Iterable<Relocation>) () -> relocationTable
				.getRelocations(fileSet)) {
			String symbolName = relocation.getSymbolName();

			if (symbolName != null && !symbolsByName.containsKey(symbolName) &&
				programSet.contains(relocation.getAddress())) {
				symbolsByName.put(symbolName, symtab.addExternalSymbol(symbolName));
			}
		}
	}

	private void addSectionNameStringTable() {
		shstrtab =
			new ElfRelocatableSectionStringTable(elf, ElfSectionHeaderConstants.dot_shstrtab);
		elf.setShStrTab(shstrtab);
	}

	private void writeOutFile(RandomAccessFile raf) throws IOException {
		elf.finalize();
		elf.write(raf, elf.getDataConverter());
	}
}
