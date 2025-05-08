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

import static ghidra.app.util.ProgramUtil.getBytes;
import static ghidra.app.util.ProgramUtil.getProgram;
import static net.boricj.bft.Utils.roundUp;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.channels.Channels;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.DropDownOption;
import ghidra.app.util.EnumDropDownOption;
import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.ProgramUtil;
import ghidra.app.util.SymbolPreference;
import ghidra.app.util.exporter.elf.relocs.ElfRelocationTableBuilder;
import ghidra.app.util.predicates.relocations.TrimSuperfluousRelativePC;
import ghidra.app.util.predicates.visibility.IsSymbolDynamic;
import ghidra.app.util.predicates.visibility.IsSymbolInsideFunction;
import ghidra.app.util.predicates.visibility.IsSymbolNameMatchingRegex;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
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
import ghidra_delinker_extension.BuildConfig;
import net.boricj.bft.Writable;
import net.boricj.bft.elf.ElfFile;
import net.boricj.bft.elf.ElfHeader;
import net.boricj.bft.elf.ElfSection;
import net.boricj.bft.elf.ElfSectionFlags;
import net.boricj.bft.elf.ElfSectionTable;
import net.boricj.bft.elf.constants.ElfClass;
import net.boricj.bft.elf.constants.ElfData;
import net.boricj.bft.elf.constants.ElfMachine;
import net.boricj.bft.elf.constants.ElfOsAbi;
import net.boricj.bft.elf.constants.ElfSectionNames;
import net.boricj.bft.elf.constants.ElfSectionType;
import net.boricj.bft.elf.constants.ElfSymbolBinding;
import net.boricj.bft.elf.constants.ElfSymbolType;
import net.boricj.bft.elf.constants.ElfType;
import net.boricj.bft.elf.sections.ElfNoBits;
import net.boricj.bft.elf.sections.ElfNullSection;
import net.boricj.bft.elf.sections.ElfProgBits;
import net.boricj.bft.elf.sections.ElfStringTable;
import net.boricj.bft.elf.sections.ElfSymbolTable;
import net.boricj.bft.elf.sections.ElfSymbolTable.ElfSymbol;

/**
 * An implementation of exporter that creates an ELF relocatable object from the
 * program.
 */
public class ElfRelocatableObjectExporter extends Exporter {
	private ElfMachine e_ident_machine;
	private ElfClass e_ident_class;
	private ElfData e_ident_data;
	private boolean generateSectionNamesStringTable;
	private boolean generateSectionComment;
	private boolean generateStringAndSymbolTables;
	private SymbolPreference symbolNamePreference;
	private boolean isDynamicSymbolLocal;
	private boolean isSymbolInsideFunctionLocal;
	private String patternSymbolNameLocal;
	private boolean generateRelocationTables;
	private ElfSectionType relocationTableFormat;
	private boolean trimSuperfluousRelativePC;

	private ElfFile elf;
	private ElfHeader header;
	private ElfSectionTable sectab;
	private ElfStringTable strtab;
	private ElfSymbolTable symtab;
	private ElfStringTable shstrtab;
	private ElfProgBits comment;

	private Program program;
	private AddressSetView fileSet;

	private RelocationTable relocationTable;
	private Predicate<Relocation> predicateRelocation;
	private Predicate<Symbol> predicateVisibility;
	private Map<Address, ElfSymbol> symbolsByAddress;
	private List<Section> sections;

	private static final SymbolPreference DEFAULT_SYMBOL_PREFERENCE = SymbolPreference.ITANIUM_ABI;

	private static final String OPTION_GROUP_ELF_HEADER = "ELF header";
	private static final String OPTION_GROUP_SYMBOLS = "Symbols";
	private static final String OPTION_GROUP_SYMBOL_VISIBILITY = "Symbol visibility";
	private static final String OPTION_GROUP_RELOCATIONS = "Relocations";

	private static final String OPTION_ELF_MACHINE = "ELF machine";
	private static final String OPTION_ELF_CLASS = "ELF class";
	private static final String OPTION_ELF_DATA = "ELF data";
	private static final String OPTION_GEN_SHSTRTAB = "Generate section names string table";
	private static final String OPTION_GEN_STRTAB = "Generate string & symbol tables";
	private static final String OPTION_PREF_SYMNAME = "Symbol name preference";
	private static final String OPTION_GEN_COMMENT = "Generate .comment section";
	private static final String OPTION_VIS_DYNAMIC = "Give dynamic symbols local visibility";
	private static final String OPTION_VIS_INSIDE_FUNCTIONS =
		"Give symbols inside functions local visibility";
	private static final String OPTION_VIS_PATTERN = "Regular expression for local symbol names";
	private static final String OPTION_GEN_REL = "Generate relocation tables";
	private static final String OPTION_REL_FMT = "Relocation table format";
	private static final String OPTION_TRIM_SUPERFLUOUS_RELATIVEPC =
		"Trim superfluous PC-relative relocations";

	private static final Map<ElfClass, String> ELF_CLASSES = new TreeMap<>(Map.ofEntries(
		Map.entry(ElfClass.ELFCLASSNONE, "(none)"),
		Map.entry(ElfClass.ELFCLASS32, "32 bits"),
		Map.entry(ElfClass.ELFCLASS64, "64 bits")));

	private static final Map<ElfData, String> ELF_DATAS = new TreeMap<>(Map.ofEntries(
		Map.entry(ElfData.ELFDATANONE, "(none)"),
		Map.entry(ElfData.ELFDATA2LSB, "Little endian"),
		Map.entry(ElfData.ELFDATA2MSB, "Big endian")));

	private static final Map<ElfMachine, String> ELF_MACHINES = new TreeMap<>(Map.ofEntries(
		Map.entry(ElfMachine.EM_NONE, "(none)"),
		Map.entry(ElfMachine.EM_386, "i386"),
		Map.entry(ElfMachine.EM_MIPS, "MIPS")));

	private static final Map<ElfSectionType, String> ELF_RELOCATION_TABLE_TYPES =
		new TreeMap<>(Map.ofEntries(
			Map.entry(ElfSectionType.SHT_NULL, "(none)"),
			Map.entry(ElfSectionType.SHT_REL, "REL"),
			Map.entry(ElfSectionType.SHT_RELA, "RELA")));

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

	private static final Map<ProcessorInfo, ElfMachine> GHIDRA_TO_ELF_MACHINES = Map.ofEntries(
		Map.entry(new ProcessorInfo("x86", 4), ElfMachine.EM_386),
		Map.entry(new ProcessorInfo("MIPS", 4), ElfMachine.EM_MIPS),
		Map.entry(new ProcessorInfo("MIPS", 8), ElfMachine.EM_MIPS),
		Map.entry(new ProcessorInfo("PSX", 4), ElfMachine.EM_MIPS));

	private static final Map<ProcessorInfo, ElfSectionType> GHIDRA_TO_ELF_RELOCATION_TYPES =
		Map.ofEntries(
			Map.entry(new ProcessorInfo("x86", 4), ElfSectionType.SHT_REL),
			Map.entry(new ProcessorInfo("x86", 8), ElfSectionType.SHT_RELA),
			Map.entry(new ProcessorInfo("MIPS", 4), ElfSectionType.SHT_REL),
			Map.entry(new ProcessorInfo("MIPS", 8), ElfSectionType.SHT_REL),
			Map.entry(new ProcessorInfo("PSX", 4), ElfSectionType.SHT_REL));

	private static ElfMachine autodetectElfMachine(Program program) {
		String processor = program.getLanguage().getProcessor().toString();
		int pointerSize = program.getDefaultPointerSize();
		ProcessorInfo info = new ProcessorInfo(processor, pointerSize);

		for (Map.Entry<ProcessorInfo, ElfMachine> entry : GHIDRA_TO_ELF_MACHINES.entrySet()) {
			if (info.equals(entry.getKey())) {
				return entry.getValue();
			}
		}

		return ElfMachine.EM_NONE;
	}

	private static ElfClass autodetectElfClass(Program program) {
		if (program.getDefaultPointerSize() == 4) {
			return ElfClass.ELFCLASS32;
		}
		else if (program.getDefaultPointerSize() == 8) {
			return ElfClass.ELFCLASS64;
		}

		return ElfClass.ELFCLASSNONE;
	}

	private static ElfData autodetectElfData(Program program) {
		if (program.getLanguage().getLanguageDescription().getEndian() == Endian.LITTLE) {
			return ElfData.ELFDATA2LSB;
		}
		else if (program.getLanguage().getLanguageDescription().getEndian() == Endian.BIG) {
			return ElfData.ELFDATA2MSB;
		}

		return ElfData.ELFDATANONE;
	}

	private static ElfSectionType autodetectElfRelocationTableFormat(Program program) {
		String processor = program.getLanguage().getProcessor().toString();
		int pointerSize = program.getDefaultPointerSize();
		ProcessorInfo info = new ProcessorInfo(processor, pointerSize);

		for (Map.Entry<ProcessorInfo, ElfSectionType> entry : GHIDRA_TO_ELF_RELOCATION_TYPES
				.entrySet()) {
			if (info.equals(entry.getKey())) {
				return entry.getValue();
			}
		}

		return ElfSectionType.SHT_NULL;
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
			new DropDownOption<ElfMachine>(OPTION_GROUP_ELF_HEADER, OPTION_ELF_MACHINE,
				ELF_MACHINES,
				ElfMachine.class, autodetectElfMachine(program)),
			new DropDownOption<ElfClass>(OPTION_GROUP_ELF_HEADER, OPTION_ELF_CLASS, ELF_CLASSES,
				ElfClass.class, autodetectElfClass(program)),
			new DropDownOption<ElfData>(OPTION_GROUP_ELF_HEADER, OPTION_ELF_DATA, ELF_DATAS,
				ElfData.class, autodetectElfData(program)),
			new Option(OPTION_GROUP_ELF_HEADER, OPTION_GEN_SHSTRTAB, true),
			new Option(OPTION_GROUP_ELF_HEADER, OPTION_GEN_COMMENT, true),
			new Option(OPTION_GROUP_SYMBOLS, OPTION_GEN_STRTAB, true),
			new Option(OPTION_GROUP_SYMBOL_VISIBILITY, OPTION_VIS_DYNAMIC, true),
			new Option(OPTION_GROUP_SYMBOL_VISIBILITY, OPTION_VIS_INSIDE_FUNCTIONS, true),
			new Option(OPTION_GROUP_SYMBOL_VISIBILITY, OPTION_VIS_PATTERN,
				IsSymbolNameMatchingRegex.DEFAULT_PATTERN),
			new EnumDropDownOption<>(OPTION_GROUP_SYMBOLS, OPTION_PREF_SYMNAME,
				SymbolPreference.class, DEFAULT_SYMBOL_PREFERENCE),
			new Option(OPTION_GROUP_RELOCATIONS, OPTION_GEN_REL, true),
			new DropDownOption<ElfSectionType>(OPTION_GROUP_RELOCATIONS, OPTION_REL_FMT,
				ELF_RELOCATION_TABLE_TYPES, ElfSectionType.class,
				autodetectElfRelocationTableFormat(program)),
			new Option(OPTION_GROUP_RELOCATIONS, OPTION_TRIM_SUPERFLUOUS_RELATIVEPC, true),
		};

		return Arrays.asList(options);
	}

	@Override
	public void setOptions(List<Option> options) {
		e_ident_machine = OptionUtils.getOption(OPTION_ELF_MACHINE, options, ElfMachine.EM_NONE);
		e_ident_class =
			OptionUtils.getOption(OPTION_ELF_CLASS, options, ElfClass.ELFCLASSNONE);
		e_ident_data = OptionUtils.getOption(OPTION_ELF_DATA, options, ElfData.ELFDATANONE);
		generateSectionNamesStringTable =
			OptionUtils.getOption(OPTION_GEN_SHSTRTAB, options, true);
		generateSectionComment = OptionUtils.getOption(OPTION_GEN_COMMENT, options, true);
		generateStringAndSymbolTables = OptionUtils.getOption(OPTION_GEN_STRTAB, options, true);
		isDynamicSymbolLocal = OptionUtils.getOption(OPTION_VIS_DYNAMIC, options, true);
		isSymbolInsideFunctionLocal =
			OptionUtils.getOption(OPTION_VIS_INSIDE_FUNCTIONS, options, true);
		patternSymbolNameLocal = OptionUtils.getOption(OPTION_VIS_PATTERN, options,
			IsSymbolNameMatchingRegex.DEFAULT_PATTERN);
		symbolNamePreference =
			OptionUtils.getOption(OPTION_PREF_SYMNAME, options, DEFAULT_SYMBOL_PREFERENCE);
		generateRelocationTables = OptionUtils.getOption(OPTION_GEN_REL, options, true);
		relocationTableFormat =
			OptionUtils.getOption(OPTION_REL_FMT, options, ElfSectionType.SHT_NULL);
		trimSuperfluousRelativePC =
			OptionUtils.getOption(OPTION_TRIM_SUPERFLUOUS_RELATIVEPC, options, false);
	}

	private class Section {
		private final MemoryBlock memoryBlock;
		private final String name;
		private final AddressSetView sectionSet;
		private byte[] bytes;

		private ElfSection section;
		private ElfSection relSection;

		public Section(MemoryBlock memoryBlock, AddressSetView sectionSet) {
			this.memoryBlock = memoryBlock;
			this.name = memoryBlock.getName();
			this.sectionSet = sectionSet;
		}

		public String getName() {
			return name;
		}

		public void createSection(boolean encodeAddend) throws MemoryAccessException {
			if (section != null) {
				throw new IllegalStateException();
			}

			ElfSectionFlags flags = new ElfSectionFlags().alloc();
			if (memoryBlock.isWrite()) {
				flags.write();
			}
			if (memoryBlock.isExecute()) {
				flags.execInstr();
			}

			if (memoryBlock.isInitialized()) {
				bytes = getBytes(program, sectionSet);
				section = new ElfProgBits(elf, name, flags, 4, bytes);
			}
			else {
				long length = sectionSet.getNumAddresses();
				section = new ElfNoBits(elf, name, flags, 4, length);
			}

			elf.getSections().add(section);
		}

		public void addSymbols() {
			symtab.addSection(section);

			ProgramUtil
					.getSectionSymbols(program, sectionSet, symbolNamePreference)
					.entrySet()
					.forEach(entry -> {
						Address address = entry.getKey();
						Symbol symbol = entry.getValue().getSymbol();
						String name = entry.getValue().getName();

						ElfSymbolType type = determineSymbolType(symbol);
						ElfSymbolBinding binding = determineSymbolBinding(symbol);
						long offset =
							ProgramUtil.getOffsetWithinAddressSet(sectionSet, symbol.getAddress());
						long size = determineSymbolSize(symbol);

						ElfSymbol sym =
							symtab.addDefined(name, offset, size, type, binding, section);
						symbolsByAddress.put(address, sym);
					});
		}

		private ElfSymbolType determineSymbolType(Symbol symbol) {
			Object obj = symbol.getObject();

			if (obj instanceof CodeUnit) {
				return ElfSymbolType.STT_OBJECT;
			}
			else if (obj instanceof Function) {
				return ElfSymbolType.STT_FUNC;
			}

			return ElfSymbolType.STT_NOTYPE;
		}

		private long determineSymbolSize(Symbol symbol) {
			Object obj = symbol.getObject();
			if (obj instanceof CodeUnit) {
				CodeUnit codeUnit = (CodeUnit) obj;

				return codeUnit.getLength();
			}
			else if (obj instanceof Function) {
				Function function = (Function) obj;

				return function.getBody().getNumAddresses();
			}

			return 0;
		}

		private ElfSymbolBinding determineSymbolBinding(Symbol symbol) {
			if (predicateVisibility.test(symbol)) {
				return ElfSymbolBinding.STB_LOCAL;
			}

			return ElfSymbolBinding.STB_GLOBAL;
		}

		public void createRelocationTableSection()
				throws MemoryAccessException {
			if (relSection != null) {
				throw new IllegalStateException();
			}

			List<Relocation> relocations = new ArrayList<>();
			relocationTable.getRelocations(sectionSet, predicateRelocation)
					.forEachRemaining(relocations::add);

			if (relocations.isEmpty()) {
				return;
			}

			ElfRelocationTableBuilder builder = findRelocationTableBuilder();
			if (builder == null) {
				log.appendMsg(section.getName(),
					"No applicable ELF relocation table builder found");
				return;
			}

			Map<Relocation, ElfSymbol> relocationsToSymbols = relocations.stream()
					.collect(Collectors.toMap(r -> r, r -> symbolsByAddress.get(r.getTarget())));

			relSection = builder.build(elf, symtab, section, bytes, sectionSet, relocations,
				relocationsToSymbols, log);
			elf.getSections().add(relSection);
		}

		private ElfRelocationTableBuilder findRelocationTableBuilder() {
			List<ElfRelocationTableBuilder> builders =
				ClassSearcher.getInstances(ElfRelocationTableBuilder.class)
						.stream()
						.filter(s -> s.canBuild(section.getElfFile(),
							relocationTableFormat))
						.collect(Collectors.toList());

			if (builders.isEmpty()) {
				return null;
			}

			ElfRelocationTableBuilder builder = builders.get(0);
			if (builders.size() > 1) {
				String msg =
					String.format(
						"Multiple applicable ELF relocation table builders found, using %s",
						builder.getClass().getName());
				log.appendMsg(section.getName(), msg);
			}

			return builder;
		}
	}

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView fileSet,
			TaskMonitor taskMonitor) throws IOException, ExporterException {
		program = ProgramUtil.getProgram(domainObj);
		if (program == null) {
			log.appendMsg("Domain object is not a program");
			return false;
		}

		Memory memory = program.getMemory();
		if (fileSet == null) {
			fileSet = memory;
		}

		this.fileSet = fileSet;
		relocationTable = RelocationTable.get(program);

		initializeRelocationPredicate();
		initializeSymbolVisibilityPredicate();

		sections = new ArrayList<>();
		for (MemoryBlock memoryBlock : program.getMemory().getBlocks()) {
			addSectionForMemoryBlock(memoryBlock);
		}

		taskMonitor.setIndeterminate(true);

		elf = new ElfFile.Builder(e_ident_class, e_ident_data, ElfOsAbi.ELFOSABI_NONE,
			ElfType.ET_REL, e_ident_machine).build();
		header = elf.getHeader();
		sectab = elf.addSectionTable();
		sectab.add(new ElfNullSection(elf));

		for (Section section : sections) {
			taskMonitor.setMessage(String.format("Creating section %s...", section.getName()));
			try {
				section.createSection(generateRelocationTables);
			}
			catch (MemoryAccessException e) {
				log.appendMsg(section.getName(), "Memory access exception: " + e.getMessage());
				return false;
			}
		}

		if (generateStringAndSymbolTables) {
			taskMonitor.setMessage("Generating symbol and string tables...");
			addStringAndSymbolTables(file);

			symtab.addFile(file.getName());
			for (Section section : sections) {
				section.addSymbols();
			}

			computeExternalSymbols();
			symtab.sort((a, b) -> a.compareTo(b));

			boolean noDuplicates = ProgramUtil.checkDuplicateSymbols(
				symtab.stream().filter(s -> s.getBinding() != ElfSymbolBinding.STB_LOCAL),
				s -> s.getName(), log);
			if (!noDuplicates) {
				return false;
			}

			if (generateRelocationTables) {
				for (Section section : sections) {
					String msg = String.format("Creating relocation table for section %s...",
						section.getName());
					taskMonitor.setMessage(msg);
					try {
						section.createRelocationTableSection();
					}
					catch (MemoryAccessException e) {
						log.appendMsg(section.getName(),
							"Memory access exception: " + e.getMessage());
						return false;
					}
				}
			}

			for (ElfSymbol symbol : symtab) {
				strtab.add(symbol.getName());
			}
		}

		if (generateSectionComment) {
			addSectionComment();
		}

		if (generateSectionNamesStringTable) {
			taskMonitor.setMessage("Generating section names string table...");
			addSectionNameStringTable();
		}

		taskMonitor.setMessage("Writing out ELF relocatable object file...");
		layoutFile();

		try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
			writeFile(raf);
		}

		return true;
	}

	private void initializeRelocationPredicate() {
		predicateRelocation = r -> true;

		if (trimSuperfluousRelativePC) {
			Predicate<Relocation> predicate = new TrimSuperfluousRelativePC(program, fileSet);
			predicateRelocation = predicateRelocation.and(predicate);
		}
	}

	private void initializeSymbolVisibilityPredicate() {
		predicateVisibility = s -> false;

		if (isDynamicSymbolLocal) {
			Predicate<Symbol> predicate = new IsSymbolDynamic();
			predicateVisibility = predicateVisibility.or(predicate);
		}

		if (isSymbolInsideFunctionLocal) {
			Predicate<Symbol> predicate = new IsSymbolInsideFunction();
			predicateVisibility = predicateVisibility.or(predicate);
		}

		if (!patternSymbolNameLocal.isBlank()) {
			Predicate<Symbol> predicate = new IsSymbolNameMatchingRegex(patternSymbolNameLocal);
			predicateVisibility = predicateVisibility.or(predicate);
		}
	}

	private void addStringAndSymbolTables(File file) {
		strtab = new ElfStringTable(elf, ElfSectionNames._STRTAB);
		strtab.add("");
		sectab.add(strtab);
		symtab = new ElfSymbolTable(elf, ElfSectionNames._SYMTAB, strtab);
		sectab.add(symtab);
		symtab.addNull();

		symbolsByAddress = new HashMap<>();
	}

	private void addSectionComment() {
		String strComment = "\0ghidra-delinker-extension " + BuildConfig.GIT_VERSION + "\0";
		byte[] bytes = strComment.getBytes(StandardCharsets.US_ASCII);
		ElfSectionFlags flags = new ElfSectionFlags().merge().strings();
		comment = new ElfProgBits(elf, ElfSectionNames._COMMENT, flags, 1, 1, bytes);
		sectab.add(comment);
	}

	private void addSectionForMemoryBlock(MemoryBlock memoryBlock) {
		AddressSet memoryBlockSet =
			new AddressSet(memoryBlock.getStart(), memoryBlock.getEnd()).intersect(fileSet);

		if (!memoryBlockSet.isEmpty()) {
			sections.add(new Section(memoryBlock, memoryBlockSet));
		}
	}

	private void computeExternalSymbols() {
		ProgramUtil.getExternalSymbols(program, fileSet, symbolNamePreference)
				.entrySet()
				.forEach(entry -> {
					Address address = entry.getKey();
					String name = entry.getValue().getName();

					ElfSymbol sym = symtab.addUndefined(name);
					symbolsByAddress.put(address, sym);
				});
	}

	private void addSectionNameStringTable() {
		shstrtab = new ElfStringTable(elf, ElfSectionNames._SHSTRTAB);
		sectab.add(shstrtab);
		elf.getHeader().setShStr(shstrtab);

		for (ElfSection section : sectab) {
			shstrtab.add(section.getName());
		}
	}

	private void layoutFile() {
		ElfHeader header = elf.getHeader();
		ElfSectionTable sections = sectab;

		long offset = header.getEhsize();
		header.setShoff(offset);
		offset += sections.getLength();

		for (ElfSection section : sections) {
			offset = roundUp(offset, section.getAddrAlign());

			section.setOffset(offset);
			offset += section.getLength();
		}
	}

	private void writeFile(RandomAccessFile raf) throws IOException {
		Collection<Writable> writables =
			Stream.concat(List.of(header, sectab).stream(), sectab.stream())
					.collect(Collectors.toList());

		try (OutputStream outputStream = Channels.newOutputStream(raf.getChannel());
				OutputStream bufferedOutputStream = new BufferedOutputStream(outputStream)) {
			Writable.write(writables, bufferedOutputStream);
		}
	}
}
