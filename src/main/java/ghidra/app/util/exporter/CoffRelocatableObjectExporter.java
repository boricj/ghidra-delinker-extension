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

import javax.help.UnsupportedOperationException;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.DropDownOption;
import ghidra.app.util.EnumDropDownOption;
import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.ProgramUtil;
import ghidra.app.util.SymbolPreference;
import ghidra.app.util.exporter.coff.relocs.CoffRelocationTableBuilder;
import ghidra.app.util.predicates.relocations.TrimSuperfluousRelativePC;
import ghidra.app.util.predicates.visibility.IsSymbolDynamic;
import ghidra.app.util.predicates.visibility.IsSymbolInsideFunction;
import ghidra.app.util.predicates.visibility.IsSymbolNameMatchingRegex;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
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
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;
import ghidra_delinker_extension.BuildConfig;
import net.boricj.bft.Writable;
import net.boricj.bft.coff.CoffFile;
import net.boricj.bft.coff.CoffHeader;
import net.boricj.bft.coff.CoffRelocationTable;
import net.boricj.bft.coff.CoffSection;
import net.boricj.bft.coff.CoffSectionTable;
import net.boricj.bft.coff.CoffStringTable;
import net.boricj.bft.coff.CoffSymbolTable;
import net.boricj.bft.coff.CoffSymbolTable.CoffSymbol;
import net.boricj.bft.coff.constants.CoffMachine;
import net.boricj.bft.coff.constants.CoffSectionFlags;
import net.boricj.bft.coff.constants.CoffStorageClass;
import net.boricj.bft.coff.sections.CoffBytes;

/**
 * An exporter implementation that exports COFF object files.
 */
public class CoffRelocatableObjectExporter extends Exporter {
	private Program program;
	private AddressSetView fileSet;
	private CoffMachine machine;
	private boolean generateSectionComment;
	private SymbolPreference symbolNamePreference;
	private boolean isDynamicSymbolStatic;
	private boolean isSymbolInsideFunctionStatic;
	private String patternSymbolNameStatic;
	private boolean trimSuperfluousRelativePC;

	private RelocationTable relocationTable;
	private Predicate<Relocation> predicateRelocation;
	private Predicate<Symbol> predicateVisibility;
	private Map<Address, CoffSymbol> symbolsByAddress;
	private List<Section> sections;

	private CoffFile coff;
	private CoffHeader header;
	private CoffSectionTable sectab;
	private CoffStringTable strtab;
	private CoffSymbolTable symtab;
	private CoffSection comment;

	private static final SymbolPreference DEFAULT_SYMBOL_PREFERENCE = SymbolPreference.MSVC;

	private static final String OPTION_GROUP_COFF_HEADER = "COFF header";
	private static final String OPTION_GROUP_SYMBOLS = "Symbols";
	private static final String OPTION_GROUP_SYMBOL_VISIBILITY = "Symbol visibility";
	private static final String OPTION_GROUP_RELOCATIONS = "Relocations";

	private static final String OPTION_COFF_MACHINE = "COFF machine";
	private static final String OPTION_GEN_COMMENT = "Generate .comment section";
	private static final String OPTION_PREF_SYMNAME = "Symbol name preference";
	private static final String OPTION_VIS_DYNAMIC = "Give dynamic symbols static visibility";
	private static final String OPTION_VIS_INSIDE_FUNCTIONS =
		"Give symbols inside functions static visibility";
	private static final String OPTION_VIS_PATTERN = "Regular expression for static symbol names";
	private static final String OPTION_TRIM_SUPERFLUOUS_RELATIVEPC =
		"Trim superfluous PC-relative relocations";

	private static final Map<CoffMachine, String> COFF_MACHINES = new TreeMap<>(Map.ofEntries(
		Map.entry(CoffMachine.IMAGE_FILE_MACHINE_UNKNOWN, "(none)"),
		Map.entry(CoffMachine.IMAGE_FILE_MACHINE_I386, "i386")));

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

	private static final Map<ProcessorInfo, CoffMachine> GHIDRA_TO_COFF_MACHINES = Map.ofEntries(
		Map.entry(new ProcessorInfo("x86", 4), CoffMachine.IMAGE_FILE_MACHINE_I386));

	private static CoffMachine autodetectCoffMachine(Program program) {
		String processor = program.getLanguage().getProcessor().toString();
		int pointerSize = program.getDefaultPointerSize();
		ProcessorInfo info = new ProcessorInfo(processor, pointerSize);

		for (Map.Entry<ProcessorInfo, CoffMachine> entry : GHIDRA_TO_COFF_MACHINES.entrySet()) {
			if (info.equals(entry.getKey())) {
				return entry.getValue();
			}
		}

		return CoffMachine.IMAGE_FILE_MACHINE_UNKNOWN;
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
			new DropDownOption<CoffMachine>(OPTION_GROUP_COFF_HEADER, OPTION_COFF_MACHINE,
				COFF_MACHINES,
				CoffMachine.class, autodetectCoffMachine(program)),
			new Option(OPTION_GROUP_COFF_HEADER, OPTION_GEN_COMMENT, true),
			new EnumDropDownOption<>(OPTION_GROUP_SYMBOLS, OPTION_PREF_SYMNAME,
				SymbolPreference.class, DEFAULT_SYMBOL_PREFERENCE),
			new Option(OPTION_GROUP_SYMBOL_VISIBILITY, OPTION_VIS_DYNAMIC, true),
			new Option(OPTION_GROUP_SYMBOL_VISIBILITY, OPTION_VIS_INSIDE_FUNCTIONS, true),
			new Option(OPTION_GROUP_SYMBOL_VISIBILITY, OPTION_VIS_PATTERN,
				IsSymbolNameMatchingRegex.DEFAULT_PATTERN),
			new Option(OPTION_GROUP_RELOCATIONS, OPTION_TRIM_SUPERFLUOUS_RELATIVEPC, true),
		};

		return Arrays.asList(options);
	}

	@Override
	public void setOptions(List<Option> options) {
		machine = OptionUtils.getOption(OPTION_COFF_MACHINE, options,
			CoffMachine.IMAGE_FILE_MACHINE_UNKNOWN);
		generateSectionComment = OptionUtils.getOption(OPTION_GEN_COMMENT, options, true);
		symbolNamePreference =
			OptionUtils.getOption(OPTION_PREF_SYMNAME, options, DEFAULT_SYMBOL_PREFERENCE);
		isDynamicSymbolStatic = OptionUtils.getOption(OPTION_VIS_DYNAMIC, options, true);
		isSymbolInsideFunctionStatic =
			OptionUtils.getOption(OPTION_VIS_INSIDE_FUNCTIONS, options, true);
		patternSymbolNameStatic = OptionUtils.getOption(OPTION_VIS_PATTERN, options,
			IsSymbolNameMatchingRegex.DEFAULT_PATTERN);
		trimSuperfluousRelativePC =
			OptionUtils.getOption(OPTION_TRIM_SUPERFLUOUS_RELATIVEPC, options, true);
	}

	private class Section {
		private final MemoryBlock memoryBlock;
		private final String name;
		private final AddressSetView sectionSet;
		private byte[] bytes;
		private CoffSection section;

		public Section(MemoryBlock memoryBlock, AddressSetView sectionSet) {
			this.memoryBlock = memoryBlock;
			this.name = memoryBlock.getName();
			this.sectionSet = sectionSet;
		}

		public String getName() {
			return name;
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

						long offset =
							ProgramUtil.getOffsetWithinAddressSet(sectionSet, symbol.getAddress());
						var obj = symbol.getObject();
						byte type = 0x00;
						if (obj instanceof Function) {
							type |= 0x20;
						}
						CoffStorageClass storageClass = CoffStorageClass.IMAGE_SYM_CLASS_EXTERNAL;
						if (predicateVisibility.test(symbol)) {
							storageClass = CoffStorageClass.IMAGE_SYM_CLASS_STATIC;
						}
						CoffSymbol sym =
							symtab.addSymbol(name, (int) offset, section, type, storageClass);
						symbolsByAddress.put(address, sym);
					});
		}

		public void buildRelocationTable(CoffMachine machine) {
			List<Relocation> relocations = new ArrayList<>();
			relocationTable.getRelocations(sectionSet, predicateRelocation)
					.forEachRemaining(relocations::add);

			List<CoffRelocationTableBuilder> builders =
				ClassSearcher.getInstances(CoffRelocationTableBuilder.class)
						.stream()
						.filter(s -> s.canBuild(machine))
						.toList();

			if (builders.isEmpty()) {
				log.appendMsg("No applicable COFF relocation table builders found");
				return;
			}

			CoffRelocationTableBuilder builder = builders.get(0);
			if (builders.size() > 1) {
				log.appendMsg("Multiple applicable COFF relocation table builders found, using " +
					builder.getClass().getName());
			}

			Map<Relocation, CoffSymbol> relocationsToSymbols = relocations.stream()
					.collect(Collectors.toMap(r -> r, r -> symbolsByAddress.get(r.getTarget())));

			builder.build(symtab, section, bytes, sectionSet, relocations, relocationsToSymbols,
				log);
		}

		public void createSection() throws MemoryAccessException {
			CoffSectionFlags characteristics = new CoffSectionFlags();
			if (memoryBlock.isRead()) {
				characteristics.memRead();
			}
			if (memoryBlock.isWrite()) {
				characteristics.memWrite();
			}
			if (memoryBlock.isExecute()) {
				characteristics.memExecute();
			}

			if (memoryBlock.isInitialized()) {
				if (memoryBlock.isExecute()) {
					characteristics.cntCode();
				}
				else {
					characteristics.cntInitializedData();
				}

				bytes = getBytes(program, sectionSet);
				section = new CoffBytes(coff, memoryBlock.getName(), characteristics, bytes);
			}
			else {
				characteristics.cntUninitializedData();
				throw new UnsupportedOperationException(
					"COFF exporter doesn't know how to handle uninitialized sections yet");
			}

			sectab.add(section);
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

		initializeRelocationPredicate();
		initializeSymbolVisibilityPredicate();

		sections = new ArrayList<>();
		for (MemoryBlock memoryBlock : program.getMemory().getBlocks()) {
			addSectionForMemoryBlock(memoryBlock);
		}

		taskMonitor.setIndeterminate(true);

		coff = new CoffFile.Builder(machine).build();
		header = coff.getHeader();
		sectab = coff.getSections();
		strtab = coff.getStrings();
		symtab = coff.getSymbols();

		for (Section section : sections) {
			taskMonitor.setMessage(String.format("Creating section %s...", section.getName()));
			try {
				section.createSection();
			}
			catch (MemoryAccessException e) {
				log.appendMsg(section.getName(), "Memory access exception: " + e.getMessage());
				return false;
			}
		}

		taskMonitor.setMessage("Generating symbol table...");
		symbolsByAddress = new HashMap<>();
		symtab.addFile(".file", file.getName());
		for (Section section : sections) {
			section.addSymbols();
		}

		computeExternalSymbols(memory);
		symtab.sort((a, b) -> a.compareTo(b));

		boolean noDuplicates = ProgramUtil.checkDuplicateSymbols(symtab.stream()
				.filter(s -> s.getStorageClass() == CoffStorageClass.IMAGE_SYM_CLASS_EXTERNAL),
			s -> s.getName(), log);
		if (!noDuplicates) {
			return false;
		}

		for (Section section : sections) {
			String msg =
				String.format("Building relocation table for section %s...", section.getName());
			taskMonitor.setMessage(msg);
			section.buildRelocationTable(machine);
		}

		if (generateSectionComment) {
			addSectionComment();
		}

		for (CoffSymbol symbol : symtab) {
			strtab.add(symbol.getName());
		}
		for (CoffSection section : sectab) {
			strtab.add(section.getName());
		}

		taskMonitor.setMessage("Writing COFF relocatable object file...");
		layoutFile();

		try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
			writeOutFile(raf);
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

		if (isDynamicSymbolStatic) {
			Predicate<Symbol> predicate = new IsSymbolDynamic();
			predicateVisibility = predicateVisibility.or(predicate);
		}

		if (isSymbolInsideFunctionStatic) {
			Predicate<Symbol> predicate = new IsSymbolInsideFunction();
			predicateVisibility = predicateVisibility.or(predicate);
		}

		if (!patternSymbolNameStatic.isBlank()) {
			Predicate<Symbol> predicate = new IsSymbolNameMatchingRegex(patternSymbolNameStatic);
			predicateVisibility = predicateVisibility.or(predicate);
		}
	}

	private void addSectionForMemoryBlock(MemoryBlock memoryBlock) {
		AddressSet memoryBlockSet =
			new AddressSet(memoryBlock.getStart(), memoryBlock.getEnd()).intersect(fileSet);

		if (!memoryBlockSet.isEmpty()) {
			sections.add(new Section(memoryBlock, memoryBlockSet));
		}
	}

	private void addSectionComment() {
		String strComment = "ghidra-delinker-extension " + BuildConfig.GIT_VERSION + "\0";
		byte[] bytes = strComment.getBytes(StandardCharsets.US_ASCII);
		CoffSectionFlags flags = new CoffSectionFlags().lnkInfo().lnkRemove();
		comment = new CoffBytes(coff, ".comment", flags, bytes);
		sectab.add(comment);
	}

	private void computeExternalSymbols(Memory memory) {
		ProgramUtil.getExternalSymbols(program, fileSet, symbolNamePreference)
				.entrySet()
				.forEach(entry -> {
					Address address = entry.getKey();
					String name = entry.getValue().getName();

					CoffSymbol sym = symtab.addUndefined(name);
					symbolsByAddress.put(address, sym);
				});
	}

	private void layoutFile() {
		long offset = sectab.getOffset() + sectab.getLength();

		for (CoffSection section : sectab) {
			CoffBytes coffBytes = (CoffBytes) section;
			byte[] data = coffBytes.getBytes();
			section.setOffset((int) offset);
			offset += data.length;

			CoffRelocationTable reltab = section.getRelocations();
			if (!reltab.isEmpty()) {
				reltab.setOffset((int) offset);
				offset += reltab.getLength();
			}
		}

		symtab.setOffset(offset);
	}

	private void writeOutFile(RandomAccessFile raf) throws IOException {
		Stream<Writable> streamWritables = Stream.of(
			List.of(header, sectab, symtab, strtab).stream(),
			sectab.stream(),
			sectab.stream().map(s -> s.getRelocations()))
				.flatMap(java.util.function.Function.identity());
		Collection<Writable> writables = streamWritables
				.collect(Collectors.toList());

		try (OutputStream outputStream = Channels.newOutputStream(raf.getChannel());
				OutputStream bufferedOutputStream = new BufferedOutputStream(outputStream)) {
			Writable.write(writables, bufferedOutputStream);
		}
	}
}
