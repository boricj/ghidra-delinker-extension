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
import java.util.HashMap;
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
import ghidra.app.util.exporter.coff.CoffRelocatableSectionRelocationTable;
import ghidra.app.util.exporter.coff.CoffRelocatableStringTable;
import ghidra.app.util.exporter.coff.CoffRelocatableSymbol;
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
	private final CoffRelocatableStringTable stringTable = new CoffRelocatableStringTable();
	private final Map<String, Integer> symbolNameToNumber = new HashMap<>();

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
					.filter(s -> s.canApply(machine))
					.toList();

		if (mappers.isEmpty()) {
			log.appendMsg("No applicable ELF relocation type mappers found");
			return null;
		}

		CoffRelocationTypeMapper mapper = mappers.get(0);
		if (mappers.size() > 1) {
			log.appendMsg("Multiple applicable ELF relocation type mappers found, using " +
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
		String symbolName = symbol.getName();
		BooleanSupplier isCdecl = () -> symbol.getObject() instanceof Function func &&
			Objects.equals(func.getCallingConventionName(), "__cdecl");
		return getCoffSymbolName(symbolName, isCdecl);
	}

	private class Section {
		private final short number;
		private final MemoryBlock memoryBlock;
		private final String name;
		private final AddressSetView sectionSet;
		private final Relocation[] relocations;
		private final byte[] data;
		private CoffRelocatableSectionRelocationTable relocationTable;

		public Section(short number, MemoryBlock memoryBlock, AddressSetView sectionSet,
				Predicate<Relocation> predicateRelocation, RelocationTable relocationTable)
				throws MemoryAccessException {
			this.number = number;
			this.memoryBlock = memoryBlock;
			this.name = memoryBlock.getName();
			this.sectionSet = sectionSet;
			List<Relocation> relocations = new ArrayList<>();
			relocationTable.getRelocations(sectionSet, predicateRelocation)
					.forEachRemaining(relocations::add);
			this.relocations = relocations.toArray(new Relocation[0]);
			if (memoryBlock.isInitialized()) {
				this.data =
					relocationTable.getOriginalBytes(sectionSet, DataConverter.getInstance(false),
						false, predicateRelocation);
			}
			else {
				this.data = null;
			}
		}

		public short headerRelocationCount() {
			if (relocations.length > 65535) {
				return (short) 65535;
			}
			else {
				return (short) relocations.length;
			}
		}

		public void addSymbols(CoffRelocatableSymbolTable.Builder symbolTableBuilder,
				CoffRelocatableStringTable stringTable) {
			AddressSet memoryBlockSet =
				new AddressSet(memoryBlock.getStart(), memoryBlock.getEnd()).intersect(fileSet);
			for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
				if (!symbol.isPrimary() || !memoryBlockSet.contains(symbol.getAddress())) {
					continue;
				}
				long offset =
					Relocation.getAddressOffsetWithinSet(memoryBlockSet, symbol.getAddress());
				String symbolName = symbol.getName();
				var obj = symbol.getObject();
				short type = 0x00;
				byte storageClass = (byte) CoffSymbolStorageClass.C_STAT;
				if (obj instanceof Function) {
					type |= 0x20;
					storageClass = CoffSymbolStorageClass.C_EXT;
				}
				var symbolBuilder =
					new CoffRelocatableSymbol.Builder(stringTable, getCoffSymbolName(symbol))
							.setValue((int) offset)
							.setSectionNumber(number)
							.setType(type)
							.setStorageClass(storageClass);
				int symbolIndex = symbolTableBuilder.addSymbol(symbolBuilder.build());
				symbolNameToNumber.put(symbolName, symbolIndex);
			}
		}

		public void buildCoffRelocationTable(CoffRelocationTypeMapper relocationTypeMapper) {
			var coffRelocationTableBuilder = new CoffRelocatableSectionRelocationTable.Builder();
			for (Relocation relocation : relocations) {
				int offset =
					(int) Relocation.getAddressOffsetWithinSet(sectionSet, relocation.getAddress());
				int symbolIndex = symbolNameToNumber.getOrDefault(relocation.getSymbolName(), -1);
				short type = relocationTypeMapper.apply(relocation, log);
				coffRelocationTableBuilder
						.addRelocation(new CoffRelocatableSectionRelocationTable.Relocation(offset,
							symbolIndex, type));
			}
			relocationTable = coffRelocationTableBuilder.build();
		}

		public CoffRelocatableSection buildCoffSection(CoffRelocatableStringTable stringTable) {
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
			return new CoffRelocatableSection.Builder(relocationTable, stringTable,
				memoryBlock.getName())
						.setCharacteristics(characteristics)
						.setData(data)
						.build();
		}
	}

	private List<Section> calculateSections(CoffRelocatableSymbolTable.Builder symbolTableBuilder,
			Predicate<Relocation> predicateRelocation, RelocationTable relocationTable)
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
					memoryBlockSet,
					predicateRelocation,
					relocationTable);
			}
			catch (MemoryAccessException e) {
				throw new ExporterException(e);
			}
			sections.add(section);
			symbolTableBuilder.addSectionSymbol(
				section.name,
				section.number,
				(int) memoryBlock.getSize(),
				section.headerRelocationCount());
			section.addSymbols(symbolTableBuilder, stringTable);
		}
		return sections;
	}

	private void calculateExternalSymbols(RelocationTable relocationTable,
			Predicate<Relocation> predicateRelocation, Memory memory,
			CoffRelocatableSymbolTable.Builder symbolTableBuilder) {
		final AddressSetView finalFileSet = fileSet;
		for (Relocation relocation : (Iterable<Relocation>) () -> relocationTable
				.getRelocations(finalFileSet, predicateRelocation)) {
			final String symbolName = relocation.getSymbolName();
			if (symbolName != null && !symbolNameToNumber.containsKey(symbolName) &&
				memory.contains(relocation.getAddress())) {
				// TODO: should plumb the symbol through instead, this is pretty convoluted and probably not right
				Optional<Symbol> symbol =
					Arrays.stream(program.getSymbolTable().getSymbols(relocation.getAddress()))
							.filter((sym -> Objects.equals(sym.getName(), symbolName)))
							.findFirst();
				String coffSymbolName = symbol.isPresent() ? getCoffSymbolName(symbol.get())
						: getCoffSymbolName(symbolName, () -> false);
				int symbolIndex = symbolTableBuilder.addSymbol(
					new CoffRelocatableSymbol.Builder(stringTable, coffSymbolName)
							.setSectionNumber((short) 0)
							.setType((short) 0x20)
							.setStorageClass((byte) CoffSymbolStorageClass.C_EXT)
							.build());
				symbolNameToNumber.put(symbolName, symbolIndex);
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

		taskMonitor.setIndeterminate(true);

		CoffRelocationTypeMapper relocationTypeMapper = findRelocationTypeMapperFor(machine, log);
		if (relocationTypeMapper == null) {
			throw new RuntimeException("No relocation type mapper found for machine");
		}

		RelocationTable relocationTable = RelocationTable.get(program);
		final AddressSetView predicateSet = fileSet;
		Predicate<Relocation> predicateRelocation =
			(Relocation r) -> r.isNeeded(program, predicateSet);
		final CoffRelocatableSymbolTable.Builder symbolTableBuilder =
			new CoffRelocatableSymbolTable.Builder(stringTable);
		symbolTableBuilder.addFileSymbol(file.getName());

		taskMonitor.setMessage("Calculating sections.");
		List<Section> sections =
			calculateSections(symbolTableBuilder, predicateRelocation, relocationTable);

		taskMonitor.setMessage("Calculating external symbols.");
		calculateExternalSymbols(relocationTable, predicateRelocation, memory, symbolTableBuilder);

		taskMonitor.setMessage("Building COFF symbol table.");
		final CoffRelocatableSymbolTable symbolTable = symbolTableBuilder.build();

		taskMonitor.setMessage("Building COFF relocation tables.");
		for (Section section : sections) {
			section.buildCoffRelocationTable(relocationTypeMapper);
		}

		taskMonitor.setMessage("Building COFF sections.");
		final CoffRelocatableObject.Builder objectBuilder =
			new CoffRelocatableObject.Builder(symbolTable, stringTable)
					.setMachine((short) machine);
		for (Section section : sections) {
			objectBuilder.addSection(section.buildCoffSection(stringTable));
		}

		taskMonitor.setMessage("Building COFF object.");
		final CoffRelocatableObject object = objectBuilder.build();

		taskMonitor.setMessage("Writing COFF object to disk.");
		try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
			object.write(raf, new LittleEndianDataConverter());
		}
		return true;
	}
}
