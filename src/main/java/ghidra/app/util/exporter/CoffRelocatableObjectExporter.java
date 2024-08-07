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

import static ghidra.app.util.ProgramUtil.getProgram;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;
import java.util.function.BooleanSupplier;
import java.util.function.Predicate;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.DropDownOption;
import ghidra.app.util.EnumDropDownOption;
import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.format.coff.CoffMachineType;
import ghidra.app.util.bin.format.coff.CoffSymbolStorageClass;
import ghidra.app.util.bin.format.pe.SectionFlags;
import ghidra.app.util.exporter.coff.CoffRelocatableObject;
import ghidra.app.util.exporter.coff.CoffRelocatableSection;
import ghidra.app.util.exporter.coff.CoffRelocatableStringTable;
import ghidra.app.util.exporter.coff.CoffRelocatableSymbolTable;
import ghidra.app.util.exporter.coff.mapper.CoffRelocationTypeMapper;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.relocobj.Relocation;
import ghidra.program.model.relocobj.RelocationTable;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.DataConverter;
import ghidra.util.LittleEndianDataConverter;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;

/**
 * An exporter implementation that exports COFF object files.
 */
public class CoffRelocatableObjectExporter extends Exporter {
	private Program program;
	private AddressSetView fileSet;
	private int machine;
	private LeadingUnderscore leadingUnderscore;

	private RelocationTable relocationTable;
	private Predicate<Relocation> predicateRelocation;

	private CoffRelocatableStringTable strtab;
	private CoffRelocatableSymbolTable symtab;

	private static final String OPTION_GROUP_COFF_HEADER = "COFF header";
	private static final String OPTION_GROUP_SYMBOLS = "Symbols";

	private static final String OPTION_COFF_MACHINE = "COFF machine";
	private static final String OPTION_LEADING_UNDERSCORE = "Leading underscore";

	private enum LeadingUnderscore {
		DO_NOTHING("Do nothing"),
		PREPEND("Prepend"),
		PREPEND_CDECL("Prepend to cdecl functions"),
		STRIP("Strip");

		private final String label;

		LeadingUnderscore(String label) {
			this.label = label;
		}

		@Override
		public String toString() {
			return label;
		}
	}

	private static final Map<Short, String> COFF_MACHINES = new TreeMap<>(Map.ofEntries(
		Map.entry(CoffMachineType.IMAGE_FILE_MACHINE_UNKNOWN, "(none)"),
		Map.entry(CoffMachineType.IMAGE_FILE_MACHINE_I386, "i386"),
		Map.entry(CoffMachineType.IMAGE_FILE_MACHINE_AMD64, "x86_64"),
		Map.entry(CoffMachineType.IMAGE_FILE_MACHINE_ARM, "ARM"),
		Map.entry(CoffMachineType.IMAGE_FILE_MACHINE_ARM64, "AARCH64"),
		Map.entry(CoffMachineType.IMAGE_FILE_MACHINE_POWERPC, "PowerPC"),
		Map.entry(CoffMachineType.IMAGE_FILE_MACHINE_RISCV32, "RISC-V"),
		Map.entry(CoffMachineType.IMAGE_FILE_MACHINE_RISCV64, "RV64"),
		Map.entry(CoffMachineType.IMAGE_FILE_MACHINE_R3000, "MIPS (R3000)"),
		Map.entry(CoffMachineType.IMAGE_FILE_MACHINE_R4000, "MIPS (R4000)")));

	private static final class ProcessorInfo {
		String processor;
		int pointerSize;

		public ProcessorInfo(String processor, int pointerSize) {
			this.processor = processor;
			this.pointerSize = pointerSize;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof ProcessorInfo info)) {
				return false;
			}

			return processor.equals(info.processor) && pointerSize == info.pointerSize;
		}

		@Override
		public int hashCode() {
			return Objects.hash(processor, pointerSize);
		}
	}

	private static final Map<ProcessorInfo, Short> GHIDRA_TO_COFF_MACHINES = Map.ofEntries(
		Map.entry(new ProcessorInfo("x86", 4), CoffMachineType.IMAGE_FILE_MACHINE_I386),
		Map.entry(new ProcessorInfo("x86", 8), CoffMachineType.IMAGE_FILE_MACHINE_AMD64),
		Map.entry(new ProcessorInfo("ARM", 4), CoffMachineType.IMAGE_FILE_MACHINE_ARM),
		Map.entry(new ProcessorInfo("AARCH64", 8), CoffMachineType.IMAGE_FILE_MACHINE_ARM64),
		Map.entry(new ProcessorInfo("PowerPC", 4), CoffMachineType.IMAGE_FILE_MACHINE_POWERPC),
		Map.entry(new ProcessorInfo("RISCV", 4), CoffMachineType.IMAGE_FILE_MACHINE_RISCV32),
		Map.entry(new ProcessorInfo("RISCV", 8), CoffMachineType.IMAGE_FILE_MACHINE_RISCV64),
		Map.entry(new ProcessorInfo("MIPS", 4), CoffMachineType.IMAGE_FILE_MACHINE_R4000),
		Map.entry(new ProcessorInfo("PSX", 4), CoffMachineType.IMAGE_FILE_MACHINE_R3000));

	private static short autodetectCoffMachine(Program program) {
		String processor = program.getLanguage().getProcessor().toString();
		int pointerSize = program.getDefaultPointerSize();
		ProcessorInfo info = new ProcessorInfo(processor, pointerSize);

		for (Map.Entry<ProcessorInfo, Short> entry : GHIDRA_TO_COFF_MACHINES.entrySet()) {
			if (info.equals(entry.getKey())) {
				return entry.getValue();
			}
		}

		return CoffMachineType.IMAGE_FILE_MACHINE_UNKNOWN;
	}

	private static LeadingUnderscore autodetectLeadingUnderscore(Program program) {
		if (autodetectCoffMachine(program) == CoffMachineType.IMAGE_FILE_MACHINE_I386) {
			return LeadingUnderscore.PREPEND;
		}
		return LeadingUnderscore.DO_NOTHING;
	}

	private static CoffRelocationTypeMapper findRelocationTypeMapperFor(
			int machine, MessageLog log) {
		List<CoffRelocationTypeMapper> mappers =
			ClassSearcher.getInstances(CoffRelocationTypeMapper.class)
					.stream()
					.filter(s -> s.canProcess(machine))
					.toList();

		if (mappers.isEmpty()) {
			log.appendMsg("No applicable COFF relocation type mappers found");
			return null;
		}

		CoffRelocationTypeMapper mapper = mappers.get(0);
		if (mappers.size() > 1) {
			log.appendMsg("Multiple applicable COFF relocation type mappers found, using " +
				mapper.getClass().getName());
		}

		return mapper;
	}

	public CoffRelocatableObjectExporter() {
		super("COFF relocatable object", "obj", null);
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		Program program = getProgram(domainObjectService.getDomainObject());
		if (program == null) {
			return EMPTY_OPTIONS;
		}

		Option[] options = new Option[] {
			new DropDownOption<>(OPTION_GROUP_COFF_HEADER, OPTION_COFF_MACHINE, COFF_MACHINES,
				Short.class, autodetectCoffMachine(program)),
			new EnumDropDownOption<>(OPTION_GROUP_SYMBOLS,
				OPTION_LEADING_UNDERSCORE, LeadingUnderscore.class,
				autodetectLeadingUnderscore(program)),
		};

		return Arrays.asList(options);
	}

	@Override
	public void setOptions(List<Option> options) {
		machine = OptionUtils.getOption(OPTION_COFF_MACHINE, options,
			CoffMachineType.IMAGE_FILE_MACHINE_UNKNOWN);
		leadingUnderscore =
			OptionUtils.getOption(OPTION_LEADING_UNDERSCORE, options, LeadingUnderscore.DO_NOTHING);
	}

	private class Section {
		private final short number;
		private final MemoryBlock memoryBlock;
		private final String name;
		private final AddressSetView sectionSet;
		private final List<Relocation> relocations;
		private final byte[] data;
		private CoffRelocatableSection section;

		public Section(short number, MemoryBlock memoryBlock, AddressSetView sectionSet)
				throws MemoryAccessException {
			this.number = number;
			this.memoryBlock = memoryBlock;
			this.name = memoryBlock.getName();
			this.sectionSet = sectionSet;
			this.relocations = new ArrayList<>();
			relocationTable.getRelocations(sectionSet, predicateRelocation)
					.forEachRemaining(relocations::add);
			if (memoryBlock.isInitialized()) {
				this.data =
					relocationTable.getOriginalBytes(sectionSet, DataConverter.getInstance(false),
						true, true, predicateRelocation);
			}
			else {
				this.data = null;
			}
		}

		public short headerRelocationCount() {
			if (relocations.size() > 65535) {
				return (short) 65535;
			}
			else {
				return (short) relocations.size();
			}
		}

		public void addSymbols() {
			AddressSet memoryBlockSet =
				new AddressSet(memoryBlock.getStart(), memoryBlock.getEnd()).intersect(fileSet);
			for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
				if (!symbol.isPrimary() || !memoryBlockSet.contains(symbol.getAddress())) {
					continue;
				}
				long offset =
					Relocation.getAddressOffsetWithinSet(memoryBlockSet, symbol.getAddress());
				String symbolName = symbol.getName(true);
				String coffSymbolName = getCoffSymbolName(symbol);
				var obj = symbol.getObject();
				short type = 0x00;
				byte storageClass = (byte) CoffSymbolStorageClass.C_STAT;
				if (obj instanceof Function) {
					type |= 0x20;
					storageClass = CoffSymbolStorageClass.C_EXT;
				}
				symtab.addDefinedSymbol(symbolName, coffSymbolName, number, (int) offset, type,
					storageClass);
			}
		}

		public void buildCoffRelocationTable(CoffRelocationTypeMapper relocationTypeMapper) {
			relocationTypeMapper.process(section.getRelocationTable(), relocations, log);
		}

		public CoffRelocatableSection buildCoffSection() {
			int characteristics = 0;
			if (memoryBlock.isRead()) {
				characteristics |= SectionFlags.IMAGE_SCN_MEM_READ.getMask();
			}
			if (memoryBlock.isWrite()) {
				characteristics |= SectionFlags.IMAGE_SCN_MEM_WRITE.getMask();
			}
			if (memoryBlock.isExecute()) {
				characteristics |= SectionFlags.IMAGE_SCN_MEM_EXECUTE.getMask();
			}
			if (memoryBlock.isInitialized()) {
				characteristics |= SectionFlags.IMAGE_SCN_CNT_INITIALIZED_DATA.getMask();
			}
			section = new CoffRelocatableSection(memoryBlock.getName(), sectionSet, characteristics,
				data, symtab, strtab);
			return section;
		}
	}

	private List<Section> calculateSections()
			throws ExporterException {
		List<Section> sections = new ArrayList<>();
		for (MemoryBlock memoryBlock : program.getMemory().getBlocks()) {
			AddressSet memoryBlockSet =
				new AddressSet(memoryBlock.getStart(), memoryBlock.getEnd()).intersect(fileSet);
			if (memoryBlockSet.isEmpty()) {
				continue;
			}
			Section section;
			try {
				section = new Section(
					(short) (sections.size() + 1),
					memoryBlock,
					memoryBlockSet);
			}
			catch (MemoryAccessException e) {
				throw new ExporterException(e);
			}
			sections.add(section);
			symtab.addSectionSymbol(
				section.name,
				section.number,
				(int) memoryBlock.getSize(),
				section.headerRelocationCount());
			section.addSymbols();
		}
		return sections;
	}

	private void calculateExternalSymbols(Memory memory) {
		final AddressSetView finalFileSet = fileSet;
		for (Relocation relocation : (Iterable<Relocation>) () -> relocationTable
				.getRelocations(finalFileSet, predicateRelocation)) {
			final String symbolName = relocation.getSymbolName();
			if (symbolName != null && symtab.getSymbolNumber(symbolName) == -1 &&
				memory.contains(relocation.getAddress())) {
				// TODO: should plumb the symbol through instead, this is pretty convoluted and probably not right
				Optional<Symbol> symbol =
					Arrays.stream(program.getSymbolTable().getSymbols(relocation.getAddress()))
							.filter((sym -> Objects.equals(sym.getName(true), symbolName)))
							.findFirst();
				String coffSymbolName = symbol.isPresent() ? getCoffSymbolName(symbol.get())
						: getCoffSymbolName(symbolName, () -> false);
				symtab.addUndefinedSymbol(symbolName, coffSymbolName);
			}
		}
	}

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView fileSet,
			TaskMonitor taskMonitor) throws ExporterException, IOException {
		program = getProgram(domainObj);
		if (program == null) {
			return false;
		}
		Memory memory = program.getMemory();
		if (fileSet == null) {
			fileSet = memory;
		}

		this.fileSet = fileSet;

		relocationTable = RelocationTable.get(program);
		final AddressSetView predicateSet = fileSet;
		predicateRelocation = (Relocation r) -> r.isNeeded(program, predicateSet);

		taskMonitor.setIndeterminate(true);

		CoffRelocationTypeMapper relocationTypeMapper = findRelocationTypeMapperFor(machine, log);
		if (relocationTypeMapper == null) {
			throw new RuntimeException("No relocation type mapper found for machine");
		}

		strtab = new CoffRelocatableStringTable();
		symtab = new CoffRelocatableSymbolTable(strtab);
		symtab.addFileSymbol(file.getName());

		taskMonitor.setMessage("Calculating sections.");
		List<Section> sections = calculateSections();

		taskMonitor.setMessage("Calculating external symbols.");
		calculateExternalSymbols(memory);

		taskMonitor.setMessage("Building COFF sections.");
		final CoffRelocatableObject object =
			new CoffRelocatableObject.Builder(symtab, strtab).setMachine((short) machine).build();
		for (Section section : sections) {
			object.addSection(section.buildCoffSection());
		}

		taskMonitor.setMessage("Building COFF relocation tables.");
		for (Section section : sections) {
			section.buildCoffRelocationTable(relocationTypeMapper);
		}

		taskMonitor.setMessage("Writing COFF object to disk.");
		try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
			object.write(raf, new LittleEndianDataConverter());
		}
		return true;
	}

	public String getCoffSymbolName(String symbolName, BooleanSupplier isCdecl) {
		switch (leadingUnderscore) {
			case PREPEND_CDECL:
				if (!isCdecl.getAsBoolean()) {
					break;
				}

			case PREPEND:
				symbolName = "_" + symbolName;
				break;

			case STRIP:
				if (symbolName.startsWith("_")) {
					symbolName = symbolName.substring(1);
				}
				break;

			default:
				break;
		}

		return symbolName;
	}

	public String getCoffSymbolName(Symbol symbol) {
		String symbolName = symbol.getName(true);
		BooleanSupplier isCdecl = () -> symbol.getObject() instanceof Function func &&
			Objects.equals(func.getCallingConventionName(), "__cdecl");
		return getCoffSymbolName(symbolName, isCdecl);
	}
}
