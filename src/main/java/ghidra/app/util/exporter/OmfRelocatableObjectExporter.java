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
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.EnumDropDownOption;
import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.ProgramUtil;
import ghidra.app.util.SymbolInformation;
import ghidra.app.util.SymbolPreference;
import ghidra.app.util.exporter.omf.relocs.OmfRelocationTableBuilder;
import ghidra.app.util.exporter.omf.relocs.OmfRelocationTableBuilder.FixupAtOffset;
import ghidra.app.util.predicates.relocations.TrimSuperfluousRelativePC;
import ghidra.app.util.predicates.visibility.IsSymbolDynamic;
import ghidra.app.util.predicates.visibility.IsSymbolInsideFunction;
import ghidra.app.util.predicates.visibility.IsSymbolNameMatchingRegex;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
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
import net.boricj.bft.omf.OmfChunkingPolicy;
import net.boricj.bft.omf.OmfFile;
import net.boricj.bft.omf.OmfRecord;
import net.boricj.bft.omf.OmfSegmentData;
import net.boricj.bft.omf.OmfUtils;
import net.boricj.bft.omf.coments.OmfComentTranslator;
import net.boricj.bft.omf.records.OmfRecordComent;
import net.boricj.bft.omf.records.OmfRecordExtdef;
import net.boricj.bft.omf.records.OmfRecordGrpdef;
import net.boricj.bft.omf.records.OmfRecordLidata;
import net.boricj.bft.omf.records.OmfRecordLnames;
import net.boricj.bft.omf.records.OmfRecordModend;
import net.boricj.bft.omf.records.OmfRecordPubdef;
import net.boricj.bft.omf.records.OmfRecordPubdef.PublicSymbol;
import net.boricj.bft.omf.records.OmfRecordSegdef;
import net.boricj.bft.omf.records.OmfRecordTheadr;
import net.boricj.bft.omf.records.OmfSubrecordExtdef;

/**
 * An exporter implementation that exports OMF (Object Module Format) object files.
 */
public class OmfRelocatableObjectExporter extends Exporter {
	private static final int DEFAULT_MAX_RECORD_SIZE = 1024;

	private static final class OmfBuilder {
		public record PublicSymbolSpec(String name, long offset, int typeIndex,
				OmfRecordGrpdef group, OmfRecordSegdef segment, int baseFrame) {
			public PublicSymbolSpec {
				Objects.requireNonNull(name);
			}
		}

		private record PubdefContextKey(OmfRecordGrpdef group, OmfRecordSegdef segment,
				int baseFrame) {}

		private final OmfFile file;
		private final Map<String, Integer> lnameIndex = new LinkedHashMap<>();
		private final List<String> lnameList = new ArrayList<>();
		private int scanCursor = 0;

		public OmfBuilder(OmfFile file) {
			this.file = Objects.requireNonNull(file);
			refreshKnownLnames();
		}

		public OmfRecordTheadr addModuleHeader(String moduleName) {
			Objects.requireNonNull(moduleName);
			if (hasRecord(OmfRecordTheadr.class)) {
				throw new IllegalStateException("THEADR already exists");
			}
			if (hasRecord(OmfRecordModend.class)) {
				throw new IllegalStateException("Cannot emit THEADR after MODEND");
			}

			OmfRecordTheadr theadr = new OmfRecordTheadr(file, moduleName);
			file.add(theadr);
			return theadr;
		}

		public OmfRecordComent addTranslatorComment(byte subtype, String translatorFingerprint) {
			Objects.requireNonNull(translatorFingerprint);
			if (hasRecord(OmfRecordModend.class)) {
				throw new IllegalStateException("Cannot emit COMENT after MODEND");
			}

			OmfRecordComent coment =
				new OmfRecordComent(file, false, false,
					new OmfComentTranslator(subtype, translatorFingerprint));
			file.add(coment);
			return coment;
		}

		public OmfRecordModend addModuleEnd() {
			if (hasRecord(OmfRecordModend.class)) {
				throw new IllegalStateException("MODEND already exists");
			}

			OmfRecordModend modend =
				new OmfRecordModend(file, false, false, new byte[0],
					OmfRecordModend.SpecificType.MODEND_32);
			file.add(modend);
			return modend;
		}

		public Map<String, Integer> reserveLnames(List<String> names) {
			Objects.requireNonNull(names);
			Map<String, Integer> indices = new LinkedHashMap<>();
			for (String name : names) {
				ensureLname(name);
				indices.putIfAbsent(name, lnameIndex.get(name));
			}
			return Map.copyOf(indices);
		}

		public OmfRecordSegdef addSegment(int attributes, long length, String segmentName,
				String className, String overlayName) {
			ensureLname(segmentName);
			ensureLname(className);
			if (!overlayName.isEmpty()) {
				ensureLname(overlayName);
			}
			var segdef =
				new OmfRecordSegdef(file, attributes, length, segmentName, className, overlayName);
			file.add(segdef);
			return segdef;
		}

		public void addExternals(List<OmfSubrecordExtdef> rows) {
			Objects.requireNonNull(rows);
			List<OmfSubrecordExtdef> safeRows = List.copyOf(rows);
			if (safeRows.isEmpty()) {
				return;
			}

			OmfUtils.emitChunkedRecords(file, safeRows,
				file.getChunkingPolicy().hardMaxSymbolAndNameRecordSize(), "EXTDEF",
				chunk -> new OmfRecordExtdef(file, chunk));
		}

		public void addPublics(List<PublicSymbolSpec> rows) {
			Objects.requireNonNull(rows);
			List<PublicSymbolSpec> safeRows = List.copyOf(rows);
			if (safeRows.isEmpty()) {
				return;
			}

			Map<PubdefContextKey, List<PublicSymbol>> symbolsByContext = new LinkedHashMap<>();
			for (PublicSymbolSpec row : safeRows) {
				if (row.segment() != null && row.baseFrame() != 0) {
					throw new IllegalArgumentException(
						"baseFrame must be zero when segment is provided: " + row.baseFrame());
				}

				PubdefContextKey key =
					new PubdefContextKey(row.group(), row.segment(), row.baseFrame());
				symbolsByContext.computeIfAbsent(key, k -> new ArrayList<>())
						.add(new PublicSymbol(row.name(), row.offset(), row.typeIndex()));
			}

			for (Map.Entry<PubdefContextKey, List<PublicSymbol>> entry : symbolsByContext
					.entrySet()) {
				PubdefContextKey key = entry.getKey();
				List<PublicSymbol> symbols = entry.getValue();
				List<PublicSymbol> run = new ArrayList<>();
				boolean runIs32Bit = symbols.get(0).offset() > 0xFFFF;

				for (PublicSymbol symbol : symbols) {
					boolean symbolIs32Bit = symbol.offset() > 0xFFFF;
					if (!run.isEmpty() && symbolIs32Bit != runIs32Bit) {
						emitPubdefRun(key, run);
						run = new ArrayList<>();
						runIs32Bit = symbolIs32Bit;
					}
					run.add(symbol);
				}
				emitPubdefRun(key, run);
			}
		}

		private void emitPubdefRun(PubdefContextKey key, List<PublicSymbol> run) {
			OmfUtils.emitChunkedRecords(
				file,
				run,
				file.getChunkingPolicy().hardMaxSymbolAndNameRecordSize(),
				"PUBDEF",
				chunk -> new OmfRecordPubdef(file, key.group(), key.segment(), key.baseFrame(),
					chunk));
		}

		private void refreshKnownLnames() {
			List<OmfRecord> records = file.getElements();
			while (scanCursor < records.size()) {
				OmfRecord record = records.get(scanCursor++);
				if (record instanceof OmfRecordLnames lnames) {
					for (String name : lnames.getNames()) {
						if (!lnameIndex.containsKey(name)) {
							int idx = lnameList.size() + 1;
							lnameIndex.put(name, idx);
							lnameList.add(name);
						}
					}
				}
			}
		}

		private void ensureLname(String name) {
			Objects.requireNonNull(name);
			refreshKnownLnames();
			if (!lnameIndex.containsKey(name)) {
				file.add(new OmfRecordLnames(file, List.of(name)));
				refreshKnownLnames();
			}
		}

		private boolean hasRecord(Class<? extends OmfRecord> recordType) {
			return file.getElements().stream().anyMatch(recordType::isInstance);
		}
	}

	private Program program;
	private AddressSetView fileSet;
	private SymbolPreference symbolNamePreference;
	private Predicate<Relocation> predicateRelocation;
	private Predicate<Symbol> predicateVisibility;
	private boolean isDynamicSymbolLocal;
	private boolean isSymbolInsideFunctionLocal;
	private String patternSymbolNameLocal;
	private int maxRecordSize = DEFAULT_MAX_RECORD_SIZE;

	private static final SymbolPreference DEFAULT_SYMBOL_PREFERENCE = SymbolPreference.MSVC;

	private static final String OPTION_GROUP_SYMBOLS = "Symbols";
	private static final String OPTION_GROUP_SYMBOL_VISIBILITY = "Symbol visibility";
	private static final String OPTION_GROUP_OMF_FORMAT = "OMF format";
	private static final String OPTION_PREF_SYMNAME = "Symbol name preference";
	private static final String OPTION_VIS_DYNAMIC = "Give dynamic symbols local visibility";
	private static final String OPTION_VIS_INSIDE_FUNCTIONS =
		"Give symbols inside functions local visibility";
	private static final String OPTION_VIS_PATTERN = "Regular expression for local symbol names";
	private static final String OPTION_MAX_RECORD_SIZE = "Maximum OMF record size";
	private static final String DEFAULT_OMF_LOCAL_SYMBOL_PATTERN =
		"(?:^LAB_.+$)|(?:" + IsSymbolNameMatchingRegex.DEFAULT_PATTERN + ")";

	static boolean validateUniqueExternalNames(List<String> names,
			ghidra.app.util.importer.MessageLog log) {
		boolean unique = ProgramUtil.checkDuplicateSymbols(names.stream(), name -> name, log);
		if (!unique) {
			log.appendMsg("OMF exporter cannot emit duplicate external names");
		}
		return unique;
	}

	static boolean validateUniquePublicNames(List<PublicSymbol> symbols,
			ghidra.app.util.importer.MessageLog log) {
		boolean unique =
			ProgramUtil.checkDuplicateSymbols(symbols.stream(), PublicSymbol::name, log);
		if (!unique) {
			log.appendMsg("OMF exporter cannot emit duplicate public names");
		}
		return unique;
	}

	public OmfRelocatableObjectExporter() {
		super("OMF relocatable object", "obj", null);
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		Program program = getProgram(domainObjectService.getDomainObject());
		if (program == null) {
			return EMPTY_OPTIONS;
		}

		Option[] options = new Option[] {
			new EnumDropDownOption<>(OPTION_GROUP_SYMBOLS, OPTION_PREF_SYMNAME,
				SymbolPreference.class, DEFAULT_SYMBOL_PREFERENCE),
			new Option(OPTION_GROUP_SYMBOL_VISIBILITY, OPTION_VIS_DYNAMIC, true),
			new Option(OPTION_GROUP_SYMBOL_VISIBILITY, OPTION_VIS_INSIDE_FUNCTIONS, true),
			new Option(OPTION_GROUP_SYMBOL_VISIBILITY, OPTION_VIS_PATTERN,
				DEFAULT_OMF_LOCAL_SYMBOL_PATTERN),
			new Option(OPTION_GROUP_OMF_FORMAT, OPTION_MAX_RECORD_SIZE, DEFAULT_MAX_RECORD_SIZE),
		};

		return java.util.Arrays.asList(options);
	}

	@Override
	public void setOptions(List<Option> options) {
		symbolNamePreference =
			OptionUtils.getOption(OPTION_PREF_SYMNAME, options, DEFAULT_SYMBOL_PREFERENCE);
		isDynamicSymbolLocal = OptionUtils.getOption(OPTION_VIS_DYNAMIC, options, true);
		isSymbolInsideFunctionLocal =
			OptionUtils.getOption(OPTION_VIS_INSIDE_FUNCTIONS, options, true);
		patternSymbolNameLocal = OptionUtils.getOption(OPTION_VIS_PATTERN, options,
			DEFAULT_OMF_LOCAL_SYMBOL_PATTERN);
		maxRecordSize = OptionUtils.getOption(OPTION_MAX_RECORD_SIZE, options,
			DEFAULT_MAX_RECORD_SIZE);
		if (maxRecordSize < 17) {
			maxRecordSize = DEFAULT_MAX_RECORD_SIZE;
		}
	}

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView fileSet,
			TaskMonitor taskMonitor) throws ExporterException, IOException {
		program = getProgram(domainObj);
		if (program == null) {
			log.appendMsg("Domain object is not a program");
			return false;
		}

		Memory memory = program.getMemory();
		if (fileSet == null) {
			fileSet = memory;
		}
		this.fileSet = fileSet;
		initializeSymbolVisibilityPredicate();

		taskMonitor.setIndeterminate(true);

		// Create OMF file
		OmfChunkingPolicy chunkingPolicy = OmfChunkingPolicy.forMaxRecordSize(maxRecordSize);
		OmfFile omf = new OmfFile.Builder()
				.setChunkingPolicy(chunkingPolicy)
				.build();

		// Create exporter-side OMF builder
		OmfBuilder builder = new OmfBuilder(omf);

		// Add THEADR record (module name)
		taskMonitor.setMessage("Creating OMF header...");
		builder.addModuleHeader(file.getName());
		String fingerprint = "ghidra-delinker-extension " + BuildConfig.GIT_VERSION;
		builder.addTranslatorComment((byte) 0x1C, fingerprint);

		// Collect all segment and class names from memory blocks
		taskMonitor.setMessage("Analyzing memory blocks...");
		List<String> lnamesList = new ArrayList<>();
		lnamesList.add(""); // Empty string is commonly first

		for (MemoryBlock memoryBlock : program.getMemory().getBlocks()) {
			AddressSet memoryBlockSet = new AddressSet(
				memoryBlock.getStart(),
				memoryBlock.getEnd()).intersect(fileSet);

			if (!memoryBlockSet.isEmpty()) {
				String segmentName = memoryBlock.getName();
				String className = getClassNameForSegment(memoryBlock);

				if (!lnamesList.contains(segmentName)) {
					lnamesList.add(segmentName);
				}
				if (!className.isEmpty() && !lnamesList.contains(className)) {
					lnamesList.add(className);
				}
			}
		}

		// Reserve all LNAMES upfront for deterministic ordering
		taskMonitor.setMessage("Reserving LNAMES...");
		builder.reserveLnames(lnamesList);

		// Create SEGDEF records for memory blocks
		taskMonitor.setMessage("Creating segment definitions...");
		List<SegmentInfo> segments = new ArrayList<>();
		for (MemoryBlock memoryBlock : program.getMemory().getBlocks()) {
			AddressSet memoryBlockSet = new AddressSet(
				memoryBlock.getStart(),
				memoryBlock.getEnd()).intersect(fileSet);

			if (memoryBlockSet.isEmpty()) {
				continue;
			}

			try {
				segments.addAll(createSegmentsForMemoryBlock(builder, memoryBlock));
			}
			catch (MemoryAccessException e) {
				log.appendMsg(memoryBlock.getName(),
					"Memory access exception: " + e.getMessage());
				return false;
			}
		}

		// Add EXTDEF records for external symbols
		taskMonitor.setMessage("Collecting external symbols...");
		Map<Address, Integer> addressToExtdefIndex = emitExternalSymbols(builder);
		if (addressToExtdefIndex == null) {
			return false;
		}

		// Add PUBDEF records for public symbols in each segment
		taskMonitor.setMessage("Collecting public symbols...");
		if (!emitPublicSymbols(builder, segments)) {
			return false;
		}

		// Add LEDATA records with segment data
		taskMonitor.setMessage("Extracting segment data...");
		RelocationTable relocationTable = RelocationTable.get(program);

		// Initialize relocation predicate to filter superfluous PC-relative relocations
		initializeRelocationPredicate();

		// Find appropriate relocation table builder
		OmfRelocationTableBuilder relocationBuilder = findRelocationTableBuilder();

		if (relocationBuilder == null) {
			log.appendMsg("No OMF relocation table builder found for language: " +
				program.getLanguage().getLanguageID());
			return false;
		}

		// Build segment mappings for intra-segment relocations
		List<OmfRelocationTableBuilder.SegmentMapping> segmentMappings =
			new ArrayList<>();
		int segmentIndex = 1;
		for (SegmentInfo segInfo : segments) {
			segmentMappings.add(new OmfRelocationTableBuilder.SegmentMapping(
				segInfo.addressSet, segmentIndex));
			segmentIndex++;
		}

		for (SegmentInfo segInfo : segments) {
			List<Relocation> segmentRelocations = new ArrayList<>();
			relocationTable.getRelocations(segInfo.addressSet, predicateRelocation)
					.forEachRemaining(segmentRelocations::add);
			segmentRelocations.sort(Comparator.comparing(Relocation::getAddress));

			if (!segInfo.isInitialized()) {
				if (!segmentRelocations.isEmpty()) {
					log.appendMsg(segInfo.memoryBlock.getName(),
						"Uninitialized OMF segment has relocations, unsupported export case");
					return false;
				}

				emitUninitializedSegmentChunks(segInfo, chunkingPolicy);
				continue;
			}

			emitSegmentChunks(relocationBuilder, segInfo, segInfo.bytes, segmentRelocations,
				segmentMappings, addressToExtdefIndex, chunkingPolicy);
		}

		// Add MODEND record
		taskMonitor.setMessage("Finalizing OMF file...");
		builder.addModuleEnd();

		// Write file
		taskMonitor.setMessage("Writing OMF relocatable object file...");
		try (FileOutputStream fos = new FileOutputStream(file)) {
			omf.write(fos);
		}

		return true;
	}

	private List<SegmentInfo> createSegmentsForMemoryBlock(OmfBuilder builder,
			MemoryBlock memoryBlock)
			throws MemoryAccessException {
		List<SegmentInfo> segments = new ArrayList<>();
		String segmentName = memoryBlock.getName();
		String className = getClassNameForSegment(memoryBlock);

		// Regular code/data/bss sections are emitted as DWORD/PUBLIC/USE32.
		int attributes = 0xA9;

		// Calculate length based on intersection with fileSet
		AddressSet memoryBlockSet = new AddressSet(
			memoryBlock.getStart(),
			memoryBlock.getEnd()).intersect(fileSet);

		if (memoryBlockSet.isEmpty()) {
			return segments;
		}

		for (AddressRange range : memoryBlockSet.getAddressRanges()) {
			AddressSet rangeSet = new AddressSet(range.getMinAddress(), range.getMaxAddress());
			long length = rangeSet.getNumAddresses();
			if (length <= 0) {
				continue;
			}

			byte[] bytes = null;
			if (memoryBlock.isInitialized()) {
				bytes = ProgramUtil.getBytes(program, rangeSet);
				if (bytes.length <= 0) {
					continue;
				}
				length = bytes.length;
			}

			OmfRecordSegdef segment =
				builder.addSegment(attributes, length, segmentName, className, "");
			segments.add(new SegmentInfo(memoryBlock, segment, rangeSet, bytes));
		}

		return segments;
	}

	private String getClassNameForSegment(MemoryBlock memoryBlock) {
		if (memoryBlock.isExecute()) {
			return "CODE";
		}
		if (!memoryBlock.isInitialized()) {
			return "BSS";
		}
		return "DATA";
	}

	private void emitUninitializedSegmentChunks(SegmentInfo segInfo,
			OmfChunkingPolicy chunkingPolicy) {
		long segmentLength = segInfo.addressSet.getNumAddresses();
		long offset = 0;
		OmfRecordSegdef segdef = segInfo.segment;

		while (offset < segmentLength) {
			long maxChunkLength = computeMaxLidataChunkLength(segdef.getFile(), segdef, offset,
				chunkingPolicy.maxRecordSize());
			if (maxChunkLength <= 0) {
				throw new IllegalStateException("OMF chunking made no forward progress for LIDATA");
			}

			long chunkLength = Math.min(segmentLength - offset, maxChunkLength);
			byte[] encodedData = encodeZeroFillLidata(chunkLength, offset > 0xFFFFL);
			segdef.getFile()
					.add(new OmfRecordLidata(segdef.getFile(), segdef, offset, encodedData));
			offset += chunkLength;
		}
	}

	private static long computeMaxLidataChunkLength(OmfFile omf, OmfRecordSegdef segment,
			long dataOffset, int maxRecordSize) {
		long overhead = new OmfRecordLidata(omf, segment, dataOffset, new byte[0]).getLength();
		int availableDataBytes = (int) Math.max(0, maxRecordSize - overhead);
		int minimumEncodedBytes = dataOffset > 0xFFFFL ? 8 : 6;
		if (availableDataBytes < minimumEncodedBytes) {
			return 0;
		}

		return dataOffset > 0xFFFFL ? 0xFFFFFFFFL : 0xFFFFL;
	}

	static byte[] encodeZeroFillLidata(long repeatCount, boolean use32BitRepeatCount) {
		long maxRepeatCount = use32BitRepeatCount ? 0xFFFFFFFFL : 0xFFFFL;
		if (repeatCount <= 0 || repeatCount > maxRepeatCount) {
			throw new IllegalArgumentException("Invalid LIDATA repeat count: " + repeatCount);
		}

		int repeatCountWidth = use32BitRepeatCount ? 4 : 2;
		byte[] encoded = new byte[repeatCountWidth + 4];
		long value = repeatCount;
		for (int i = 0; i < repeatCountWidth; i++) {
			encoded[i] = (byte) (value & 0xFF);
			value >>>= 8;
		}

		encoded[repeatCountWidth] = 0;
		encoded[repeatCountWidth + 1] = 0;
		encoded[repeatCountWidth + 2] = 1;
		encoded[repeatCountWidth + 3] = 0;
		return encoded;
	}

	private Map<Address, Integer> emitExternalSymbols(OmfBuilder builder) {
		Map<Address, SymbolInformation> externalSymbols =
			ProgramUtil.getExternalSymbols(program, fileSet, symbolNamePreference);
		List<OmfSubrecordExtdef> externalRows = new ArrayList<>();
		Map<Address, Integer> addressToExtdefIndex = new HashMap<>();
		if (externalSymbols.isEmpty()) {
			return addressToExtdefIndex;
		}

		int index = 1;
		List<Map.Entry<Address, SymbolInformation>> sortedExternalSymbols =
			externalSymbols.entrySet()
					.stream()
					.sorted((a, b) -> {
						String nameA = a.getValue().getName();
						String nameB = b.getValue().getName();
						int cmp = nameA.compareTo(nameB);
						if (cmp != 0) {
							return cmp;
						}
						return a.getKey().compareTo(b.getKey());
					})
					.toList();

		List<String> extdefNames = new ArrayList<>();
		for (Map.Entry<Address, SymbolInformation> entry : sortedExternalSymbols) {
			String extdefName = entry.getValue().getName();
			extdefNames.add(extdefName);
			externalRows.add(new OmfSubrecordExtdef(extdefName, 0));
			addressToExtdefIndex.put(entry.getKey(), index);
			index++;
		}

		if (!validateUniqueExternalNames(extdefNames, log)) {
			return null;
		}

		builder.addExternals(externalRows);
		return addressToExtdefIndex;
	}

	private boolean emitPublicSymbols(OmfBuilder builder, List<SegmentInfo> segments) {
		List<OmfBuilder.PublicSymbolSpec> publicRows = new ArrayList<>();
		List<PublicSymbol> allPublicSymbols = new ArrayList<>();

		for (SegmentInfo segInfo : segments) {
			Map<Address, SymbolInformation> sectionSymbols =
				ProgramUtil.getSectionSymbols(program, segInfo.addressSet, symbolNamePreference);
			if (sectionSymbols.isEmpty()) {
				continue;
			}

			List<Map.Entry<Address, SymbolInformation>> sortedSectionSymbols =
				sectionSymbols.entrySet()
						.stream()
						.sorted((a, b) -> {
							int cmp = a.getKey().compareTo(b.getKey());
							if (cmp != 0) {
								return cmp;
							}

							String nameA = a.getValue().getName();
							String nameB = b.getValue().getName();
							return nameA.compareTo(nameB);
						})
						.toList();

			for (Map.Entry<Address, SymbolInformation> entry : sortedSectionSymbols) {
				Symbol symbol = entry.getValue().getSymbol();
				if (predicateVisibility.test(symbol)) {
					continue;
				}

				Address address = entry.getKey();
				String name = entry.getValue().getName();
				long offset = ProgramUtil.getOffsetWithinAddressSet(segInfo.addressSet, address);
				PublicSymbol publicSymbol = new PublicSymbol(name, offset, 0);

				publicRows.add(new OmfBuilder.PublicSymbolSpec(name, offset, 0,
					(OmfRecordGrpdef) null, segInfo.segment, 0));
				allPublicSymbols.add(publicSymbol);
			}
		}

		if (!validateUniquePublicNames(allPublicSymbols, log)) {
			return false;
		}

		builder.addPublics(publicRows);
		return true;
	}

	private OmfRelocationTableBuilder findRelocationTableBuilder() {
		List<OmfRelocationTableBuilder> builders = ClassSearcher
				.getInstances(OmfRelocationTableBuilder.class)
				.stream()
				.filter(builder -> builder.canBuild(program.getLanguage()))
				.toList();

		if (builders.isEmpty()) {
			return null;
		}

		OmfRelocationTableBuilder builder = builders.get(0);
		if (builders.size() > 1) {
			log.appendMsg("Multiple applicable OMF relocation table builders found, using " +
				builder.getClass().getName());
		}
		return builder;
	}

	private void emitSegmentChunks(OmfRelocationTableBuilder relocationBuilder,
			SegmentInfo segInfo, byte[] bytes, List<Relocation> segmentRelocations,
			List<OmfRelocationTableBuilder.SegmentMapping> segmentMappings,
			Map<Address, Integer> addressToExtdefIndex, OmfChunkingPolicy chunkingPolicy) {
		OmfRecordSegdef segdef = segInfo.segment;
		List<FixupAtOffset> fixupsAtOffsets =
			relocationBuilder.build(segdef, addressToExtdefIndex,
				bytes, segInfo.addressSet, segmentRelocations, segmentMappings, log);
		fixupsAtOffsets.sort(Comparator.comparingInt(FixupAtOffset::segmentOffset));
		List<OmfSegmentData.FixupAtOffset> segmentFixups = fixupsAtOffsets.stream()
				.map(f -> new OmfSegmentData.FixupAtOffset(f.segmentOffset(), f.entry()))
				.toList();
		new OmfSegmentData(segdef, bytes, segmentFixups).emit(segdef.getFile(), chunkingPolicy);
	}

	private static class SegmentInfo {
		final MemoryBlock memoryBlock;
		final OmfRecordSegdef segment;
		final AddressSet addressSet;
		final byte[] bytes;

		SegmentInfo(MemoryBlock memoryBlock, OmfRecordSegdef segment, AddressSet addressSet,
				byte[] bytes) {
			this.memoryBlock = memoryBlock;
			this.segment = segment;
			this.addressSet = addressSet;
			this.bytes = bytes;
		}

		boolean isInitialized() {
			return bytes != null;
		}
	}

	private void initializeRelocationPredicate() {
		predicateRelocation = new TrimSuperfluousRelativePC(program, fileSet);
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
}
