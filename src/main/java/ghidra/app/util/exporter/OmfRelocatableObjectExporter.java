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
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

import ghidra.app.util.DomainObjectService;
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
import net.boricj.bft.omf.coments.OmfComentTranslator;
import net.boricj.bft.omf.logical.OmfExtdefData;
import net.boricj.bft.omf.logical.OmfLnamesData;
import net.boricj.bft.omf.logical.OmfPubdefData;
import net.boricj.bft.omf.logical.OmfSegmentData;
import net.boricj.bft.omf.records.OmfRecordComent;
import net.boricj.bft.omf.records.OmfRecordModend;
import net.boricj.bft.omf.records.OmfRecordPubdef.PublicSymbol;
import net.boricj.bft.omf.records.OmfRecordSegdef;
import net.boricj.bft.omf.records.OmfRecordSegdef.Attributes;
import net.boricj.bft.omf.records.OmfRecordTheadr;

/**
 * An exporter implementation that exports OMF (Object Module Format) object files.
 */
public class OmfRelocatableObjectExporter extends Exporter {
	private static final int DEFAULT_MAX_RECORD_SIZE = 1024;

	private Program program;
	private AddressSetView fileSet;
	private Predicate<Relocation> predicateRelocation;
	private Predicate<Symbol> predicateVisibility;
	private boolean isDynamicSymbolLocal;
	private boolean isSymbolInsideFunctionLocal;
	private String patternSymbolNameLocal;
	private int maxRecordSize = DEFAULT_MAX_RECORD_SIZE;

	private static final String OPTION_GROUP_SYMBOL_VISIBILITY = "Symbol visibility";
	private static final String OPTION_GROUP_OMF_FORMAT = "OMF format";
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

		// Add THEADR record (module name)
		taskMonitor.setMessage("Creating OMF header...");
		omf.add(new OmfRecordTheadr(omf, file.getName()));
		addTranslatorComment(omf);

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

		// Add LNAMES record
		taskMonitor.setMessage("Creating LNAMES...");
		new OmfLnamesData(lnamesList).emit(omf, chunkingPolicy);

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

			if (!memoryBlock.isInitialized()) {
				log.appendMsg(memoryBlock.getName(),
					"OMF exporter does not support uninitialized memory blocks yet");
				return false;
			}

			try {
				SegmentInfo segInfo = createSegmentForMemoryBlock(omf, memoryBlock);
				if (segInfo != null) {
					segments.add(segInfo);
				}
			}
			catch (MemoryAccessException e) {
				log.appendMsg(memoryBlock.getName(),
					"Memory access exception: " + e.getMessage());
				return false;
			}
		}

		// Add EXTDEF records for external symbols
		taskMonitor.setMessage("Collecting external symbols...");
		Map<Address, Integer> addressToExtdefIndex = emitExternalSymbols(omf, chunkingPolicy);
		if (addressToExtdefIndex == null) {
			return false;
		}

		// Add PUBDEF records for public symbols in each segment
		taskMonitor.setMessage("Collecting public symbols...");
		if (!emitPublicSymbols(omf, chunkingPolicy, segments)) {
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
			try {
				byte[] bytes = ProgramUtil.getBytes(program, segInfo.addressSet);
				List<Relocation> segmentRelocations = new ArrayList<>();
				relocationTable.getRelocations(segInfo.addressSet, predicateRelocation)
						.forEachRemaining(segmentRelocations::add);
				segmentRelocations.sort(Comparator.comparing(Relocation::getAddress));

				emitSegmentChunks(omf, relocationBuilder, segInfo, bytes, segmentRelocations,
					segmentMappings, addressToExtdefIndex, chunkingPolicy);
			}
			catch (MemoryAccessException e) {
				log.appendMsg(segInfo.memoryBlock.getName(),
					"Memory access exception: " + e.getMessage());
				return false;
			}
		}

		// Add MODEND record
		taskMonitor.setMessage("Finalizing OMF file...");
		omf.add(new OmfRecordModend(omf, false, false, new byte[0]));

		// Write file
		taskMonitor.setMessage("Writing OMF relocatable object file...");
		try (FileOutputStream fos = new FileOutputStream(file)) {
			omf.write(fos);
		}

		return true;
	}

	private SegmentInfo createSegmentForMemoryBlock(OmfFile omf, MemoryBlock memoryBlock)
			throws MemoryAccessException {
		String segmentName = memoryBlock.getName();
		String className = getClassNameForSegment(memoryBlock);

		// Create attributes (A=9 for alignment, C=5 for public combine, B=0, P=1 for 32-bit).
		// Use execute permissions to decide code-vs-data semantics.
		int attributes = memoryBlock.isExecute() ? 0x6D : 0x69;

		// Calculate length based on intersection with fileSet
		AddressSet memoryBlockSet = new AddressSet(
			memoryBlock.getStart(),
			memoryBlock.getEnd()).intersect(fileSet);

		if (memoryBlockSet.isEmpty()) {
			return null;
		}

		byte[] bytes = ProgramUtil.getBytes(program, memoryBlockSet);
		if (bytes.length <= 0) {
			return null;
		}

		Address start = memoryBlockSet.getMinAddress();
		Address end = start.add(bytes.length - 1);
		AddressSet trimmedSet = new AddressSet(start, end);
		long length = trimmedSet.getNumAddresses();

		OmfRecordSegdef segdef = new OmfRecordSegdef(omf, Attributes.ofRaw(attributes), length,
			segmentName, className, "");
		omf.add(segdef);

		return new SegmentInfo(memoryBlock, segdef, trimmedSet);
	}

	private String getClassNameForSegment(MemoryBlock memoryBlock) {
		if (memoryBlock.isExecute()) {
			return "CODE";
		}
		return "DATA";
	}

	private Map<Address, Integer> emitExternalSymbols(OmfFile omf,
			OmfChunkingPolicy chunkingPolicy) {
		Map<Address, SymbolInformation> externalSymbols =
			ProgramUtil.getExternalSymbols(program, fileSet, SymbolPreference.MSVC);
		List<String> extdefNames = new ArrayList<>();
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

		for (Map.Entry<Address, SymbolInformation> entry : sortedExternalSymbols) {
			String extdefName = entry.getValue().getName();
			extdefNames.add(extdefName);
			addressToExtdefIndex.put(entry.getKey(), index);
			index++;
		}

		if (!validateUniqueExternalNames(extdefNames, log)) {
			return null;
		}

		OmfExtdefData.fromNames(extdefNames, 0).emit(omf, chunkingPolicy);
		return addressToExtdefIndex;
	}

	private boolean emitPublicSymbols(OmfFile omf, OmfChunkingPolicy chunkingPolicy,
			List<SegmentInfo> segments) {
		List<SegmentPublicSymbols> publicSymbolsBySegment = new ArrayList<>();
		List<PublicSymbol> allPublicSymbols = new ArrayList<>();

		for (SegmentInfo segInfo : segments) {
			Map<Address, SymbolInformation> sectionSymbols =
				ProgramUtil.getSectionSymbols(program, segInfo.addressSet, SymbolPreference.MSVC);
			if (sectionSymbols.isEmpty()) {
				continue;
			}

			List<PublicSymbol> pubdefSymbols = new ArrayList<>();
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
				pubdefSymbols.add(publicSymbol);
				allPublicSymbols.add(publicSymbol);
			}

			if (!pubdefSymbols.isEmpty()) {
				publicSymbolsBySegment.add(new SegmentPublicSymbols(segInfo, pubdefSymbols));
			}
		}

		if (!validateUniquePublicNames(allPublicSymbols, log)) {
			return false;
		}

		for (SegmentPublicSymbols segmentPublicSymbols : publicSymbolsBySegment) {
			new OmfPubdefData(null, segmentPublicSymbols.segmentInfo().segdef, 0,
				segmentPublicSymbols.publicSymbols()).emit(omf, chunkingPolicy);
		}

		return true;
	}

	private void addTranslatorComment(OmfFile omf) {
		String fingerprint = "ghidra-delinker-extension " + BuildConfig.GIT_VERSION;
		OmfComentTranslator translator = new OmfComentTranslator((byte) 0x1C, fingerprint);
		omf.add(new OmfRecordComent(omf, false, false, translator));
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

	private void emitSegmentChunks(OmfFile omf, OmfRelocationTableBuilder relocationBuilder,
			SegmentInfo segInfo, byte[] bytes, List<Relocation> segmentRelocations,
			List<OmfRelocationTableBuilder.SegmentMapping> segmentMappings,
			Map<Address, Integer> addressToExtdefIndex, OmfChunkingPolicy chunkingPolicy) {
		List<FixupAtOffset> fixupsAtOffsets =
			relocationBuilder.build(segInfo.segdef, addressToExtdefIndex,
				bytes, segInfo.addressSet, segmentRelocations, segmentMappings, log);
		fixupsAtOffsets.sort(Comparator.comparingInt(FixupAtOffset::segmentOffset));
		List<OmfSegmentData.FixupAtOffset> segmentFixups = fixupsAtOffsets.stream()
				.map(f -> new OmfSegmentData.FixupAtOffset(f.segmentOffset(), f.entry()))
				.toList();
		new OmfSegmentData(segInfo.segdef, bytes, segmentFixups).emit(omf, chunkingPolicy);
	}

	private static class SegmentInfo {
		final MemoryBlock memoryBlock;
		final OmfRecordSegdef segdef;
		final AddressSet addressSet;

		SegmentInfo(MemoryBlock memoryBlock, OmfRecordSegdef segdef, AddressSet addressSet) {
			this.memoryBlock = memoryBlock;
			this.segdef = segdef;
			this.addressSet = addressSet;
		}
	}

	private static record SegmentPublicSymbols(SegmentInfo segmentInfo,
			List<PublicSymbol> publicSymbols) {}

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
