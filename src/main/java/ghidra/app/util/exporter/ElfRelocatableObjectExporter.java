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
import java.util.function.Predicate;
import java.util.stream.Collectors;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.DropDownOption;
import ghidra.app.util.EnumDropDownOption;
import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.ProgramUtil;
import ghidra.app.util.SymbolPreference;
import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.exporter.elf.ElfRelocatableObject;
import ghidra.app.util.exporter.elf.ElfRelocatableSection;
import ghidra.app.util.exporter.elf.ElfRelocatableSectionComment;
import ghidra.app.util.exporter.elf.ElfRelocatableSectionNoBits;
import ghidra.app.util.exporter.elf.ElfRelocatableSectionProgBits;
import ghidra.app.util.exporter.elf.ElfRelocatableSectionStringTable;
import ghidra.app.util.exporter.elf.ElfRelocatableSectionSymbolTable;
import ghidra.app.util.exporter.elf.ElfRelocatableSymbol;
import ghidra.app.util.exporter.elf.relocs.ElfRelocationTableBuilder;
import ghidra.app.util.visibility.IsSymbolDynamic;
import ghidra.app.util.visibility.IsSymbolInsideFunction;
import ghidra.app.util.visibility.IsSymbolNameMatchingRegex;
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
import ghidra_delinker_extension.BuildConfig;

/**
 * An implementation of exporter that creates an ELF relocatable object from the
 * program.
 */
public class ElfRelocatableObjectExporter extends Exporter {
	private short e_ident_machine;
	private byte e_ident_class;
	private byte e_ident_data;
	private boolean generateSectionNamesStringTable;
	private boolean generateSectionComment;
	private boolean generateStringAndSymbolTables;
	private SymbolPreference symbolNamePreference;
	private boolean isDynamicSymbolLocal;
	private boolean isSymbolInsideFunctionLocal;
	private String patternSymbolNameLocal;
	private boolean generateRelocationTables;
	private int relocationTableFormat;

	private ElfRelocatableObject elf;
	private ElfRelocatableSectionStringTable strtab;
	private ElfRelocatableSectionSymbolTable symtab;
	private ElfRelocatableSectionStringTable shstrtab;
	@SuppressWarnings("unused")
	private ElfRelocatableSectionComment comment;

	private Program program;
	private AddressSetView fileSet;

	private RelocationTable relocationTable;
	private Predicate<Relocation> predicateRelocation;
	private Predicate<Symbol> predicateVisibility;
	private Map<String, ElfRelocatableSymbol> symbolsByName;
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
			new DropDownOption<Short>(OPTION_GROUP_ELF_HEADER, OPTION_ELF_MACHINE, ELF_MACHINES,
				Short.class, autodetectElfMachine(program)),
			new DropDownOption<Byte>(OPTION_GROUP_ELF_HEADER, OPTION_ELF_CLASS, ELF_CLASSES,
				Byte.class, autodetectElfClass(program)),
			new DropDownOption<Byte>(OPTION_GROUP_ELF_HEADER, OPTION_ELF_DATA, ELF_DATAS,
				Byte.class, autodetectElfData(program)),
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
			new DropDownOption<Integer>(OPTION_GROUP_RELOCATIONS, OPTION_REL_FMT,
				ELF_RELOCATION_TABLE_TYPES, Integer.class,
				autodetectElfRelocationTableFormat(program))
		};

		return Arrays.asList(options);
	}

	@Override
	public void setOptions(List<Option> options) {
		e_ident_machine = OptionUtils.getOption(OPTION_ELF_MACHINE, options, ElfConstants.EM_NONE);
		e_ident_class =
			OptionUtils.getOption(OPTION_ELF_CLASS, options, ElfConstants.ELF_CLASS_NONE);
		e_ident_data = OptionUtils.getOption(OPTION_ELF_DATA, options, ElfConstants.ELF_DATA_NONE);
		generateSectionNamesStringTable =
			OptionUtils.getOption(OPTION_GEN_SHSTRTAB, options, false);
		generateSectionComment = OptionUtils.getOption(OPTION_GEN_COMMENT, options, false);
		generateStringAndSymbolTables = OptionUtils.getOption(OPTION_GEN_STRTAB, options, false);
		isDynamicSymbolLocal = OptionUtils.getOption(OPTION_VIS_DYNAMIC, options, true);
		isSymbolInsideFunctionLocal =
			OptionUtils.getOption(OPTION_VIS_INSIDE_FUNCTIONS, options, true);
		patternSymbolNameLocal = OptionUtils.getOption(OPTION_VIS_PATTERN, options,
			IsSymbolNameMatchingRegex.DEFAULT_PATTERN);
		symbolNamePreference =
			OptionUtils.getOption(OPTION_PREF_SYMNAME, options, DEFAULT_SYMBOL_PREFERENCE);
		generateRelocationTables = OptionUtils.getOption(OPTION_GEN_REL, options, false);
		relocationTableFormat =
			OptionUtils.getOption(OPTION_REL_FMT, options, ElfSectionHeaderConstants.SHT_NULL);
	}

	private class Section {
		private final MemoryBlock memoryBlock;
		private final String name;
		private final AddressSetView sectionSet;
		private byte[] bytes;

		private ElfRelocatableSection section;
		private ElfRelocatableSection relSection;

		public Section(MemoryBlock memoryBlock, AddressSetView sectionSet) {
			this.memoryBlock = memoryBlock;
			this.name = memoryBlock.getName();
			this.sectionSet = sectionSet;
		}

		public String getName() {
			return name;
		}

		public void createElfSection(boolean encodeAddend) throws MemoryAccessException {
			if (section != null) {
				throw new IllegalStateException();
			}

			long flags = ElfSectionHeaderConstants.SHF_ALLOC;
			flags |= memoryBlock.isWrite() ? ElfSectionHeaderConstants.SHF_WRITE : 0;
			flags |= memoryBlock.isExecute() ? ElfSectionHeaderConstants.SHF_EXECINSTR : 0;

			if (memoryBlock.isInitialized()) {
				bytes = getBytes(program, sectionSet);
				section = new ElfRelocatableSectionProgBits(elf, name, bytes, sectionSet, flags);
			}
			else {
				long length = sectionSet.getNumAddresses();
				section = new ElfRelocatableSectionNoBits(elf, name, length, sectionSet, flags);
			}
		}

		public void addSymbols() {
			symtab.addSectionSymbol(section);

			ProgramUtil.getSectionSymbols(program, sectionSet, symbolNamePreference)
					.entrySet()
					.forEach(entry -> {
						Symbol symbol = entry.getValue();
						String symbolName = symbol.getName(true);
						byte type = determineSymbolType(symbol);
						byte visibility = determineSymbolVisibility(symbol);
						long offset =
							ProgramUtil.getOffsetWithinAddressSet(sectionSet, symbol.getAddress());
						long size = determineSymbolSize(symbol);

						symbolsByName.put(entry.getKey(),
							symtab.addDefinedSymbol(section, symbolName, visibility, type, size,
								offset));
					});
		}

		private byte determineSymbolType(Symbol symbol) {
			Object obj = symbol.getObject();

			if (obj instanceof CodeUnit) {
				return ElfSymbol.STT_OBJECT;
			}
			else if (obj instanceof Function) {
				return ElfSymbol.STT_FUNC;
			}

			return ElfSymbol.STT_NOTYPE;
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

		private byte determineSymbolVisibility(Symbol symbol) {
			if (predicateVisibility.test(symbol)) {
				return ElfSymbol.STB_LOCAL;
			}

			return ElfSymbol.STB_GLOBAL;
		}

		public void createElfRelocationTableSection()
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

			List<ElfRelocationTableBuilder> builders =
				ClassSearcher.getInstances(ElfRelocationTableBuilder.class)
						.stream()
						.filter(s -> s.canBuild(section.getElfRelocatableObject(),
							relocationTableFormat))
						.collect(Collectors.toList());

			if (builders.isEmpty()) {
				log.appendMsg(section.getName(),
					"No applicable ELF relocation table builder found");
				return;
			}

			ElfRelocationTableBuilder builder = builders.get(0);
			if (builders.size() > 1) {
				String msg =
					String.format(
						"Multiple applicable ELF relocation table builders found, using %s",
						builder.getClass().getName());
				log.appendMsg(section.getName(), msg);
			}

			relSection = builder.build(elf, symtab, section, bytes, sectionSet, relocations, log);
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

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView fileSet,
			TaskMonitor taskMonitor) throws IOException, ExporterException {
		program = ProgramUtil.getProgram(domainObj);
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
		initializeSymbolVisibilityPredicate();

		sections = new ArrayList<>();
		for (MemoryBlock memoryBlock : program.getMemory().getBlocks()) {
			addSectionForMemoryBlock(memoryBlock);
		}

		taskMonitor.setIndeterminate(true);

		try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
			elf = new ElfRelocatableObject.Builder(file.getName())
					.setType(ElfConstants.ET_REL)
					.setMachine(e_ident_machine)
					.setClass(e_ident_class)
					.setData(e_ident_data)
					.build();

			if (generateSectionComment) {
				addSectionComment();
			}

			if (generateStringAndSymbolTables) {
				addStringAndSymbolTables();
			}

			for (Section section : sections) {
				taskMonitor.setMessage(String.format("Creating section %s...", section.getName()));
				section.createElfSection(generateRelocationTables);
			}

			if (generateStringAndSymbolTables) {
				taskMonitor.setMessage("Generating symbol table...");

				for (Section section : sections) {
					section.addSymbols();
				}

				computeExternalSymbols();

				if (generateRelocationTables) {
					for (Section section : sections) {
						String msg = String.format("Creating relocation table for section %s...",
							section.getName());
						taskMonitor.setMessage(msg);
						section.createElfRelocationTableSection();
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

	private void addStringAndSymbolTables() {
		strtab = new ElfRelocatableSectionStringTable(elf, ElfSectionHeaderConstants.dot_strtab);
		symtab =
			new ElfRelocatableSectionSymbolTable(elf, ElfSectionHeaderConstants.dot_symtab, strtab);
		symtab.addFileSymbol(elf.getFileName());

		symbolsByName = new HashMap<>();
	}

	private void addSectionComment() {
		String strComment = "ghidra-delinker-extension " + BuildConfig.GIT_VERSION;
		comment = new ElfRelocatableSectionComment(elf, ".comment", strComment);
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
					symbolsByName.put(entry.getKey(),
						symtab.addExternalSymbol(entry.getValue().getName(true)));
				});
	}

	private void addSectionNameStringTable() {
		shstrtab =
			new ElfRelocatableSectionStringTable(elf, ElfSectionHeaderConstants.dot_shstrtab);
		elf.setShStrTab(shstrtab);
	}

	private void writeOutFile(RandomAccessFile raf) throws IOException {
		elf.layout();
		elf.write(raf, elf.getDataConverter());
	}
}
