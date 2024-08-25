//Delink and export a piece of the program in headless mode.
//@author Jean-Baptiste Boric
//@category Project
//@keybinding
//@menupath
//@toolbar

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.Analyzer;
import ghidra.app.util.Option;
import ghidra.app.util.OptionException;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.module.TreeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.classfinder.ClassSearcher;

public class DelinkProgram extends HeadlessScript {
	private static final Pattern TREEPATH_PATTERN = Pattern.compile("^([^:]+):([^/]+(?:/[^/]+)*)$");

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();

		AddressSet addressSet = new AddressSet();
		File file = null;
		Exporter exporter = null;

		for (int i = 0; i < args.length; i++) {
			switch (args[i]) {
				case "/exporter":
					exporter = findExporter(args[++i]);
					break;
				case "/export":
					file = new File(args[++i]);
					export(file, exporter, addressSet);
					addressSet = new AddressSet();
					break;
				case "/include-tree":
					addressSet.add(findProgramModule(args[++i]));
					break;
				case "/exclude-tree":
					addressSet.delete(findProgramModule(args[++i]));
					break;
				case "/include-block":
					addressSet.add(findBlock(args[++i]));
					break;
				case "/exclude-block":
					addressSet.delete(findBlock(args[++i]));
					break;
				case "/include-range":
					addressSet.add(findRange(args[++i]));
					break;
				case "/exclude-range":
					addressSet.delete(findRange(args[++i]));
					break;
				case "/include-file":
					addressSet.add(findSymbolsInFile(args[++i]));
					break;
				case "/exclude-file":
					addressSet.delete(findSymbolsInFile(args[++i]));
					break;
				case "/include":
					addressSet.add(findSymbol(args[++i]));
					break;
				case "/exclude":
					addressSet.delete(findSymbol(args[++i]));
					break;
				default:
					throw new RuntimeException("Unknown argument " + args[i]);
			}
		}
	}

	void export(File file, Exporter exporter, AddressSet addressSet)
			throws OptionException, ExporterException, IOException {
		AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(currentProgram);
		Analyzer analyzer = aam.getAnalyzer("Relocation table synthesizer");
		aam.scheduleOneTimeAnalysis(analyzer, addressSet);
		aam.waitForAnalysis(null, getMonitor());

		exporter.setOptions(getOptions(exporter));
		if (!exporter.export(file, currentProgram, addressSet, monitor)) {
			throw new RuntimeException("Failed to export " + file.getName());
		}
	}

	AddressSetView findProgramModule(String path) {
		Matcher matcher = TREEPATH_PATTERN.matcher(path);
		if (!matcher.matches()) {
			throw new RuntimeException("Invalid tree path " + path);
		}

		TreeManager treeManager = ((ProgramDB) currentProgram).getTreeManager();
		ProgramModule module = treeManager.getRootModule(matcher.group(1));

		for (String part : matcher.group(2).split("/")) {
			module = (ProgramModule) module.getChildren()[module.getIndex(part)];
		}

		return module.getAddressSet();
	}

	AddressSetView findBlock(String name) {
		Memory memory = currentProgram.getMemory();
		MemoryBlock block = memory.getBlock(name);
		AddressFactory addressFactory = currentProgram.getAddressFactory();
		return addressFactory.getAddressSet(block.getStart(), block.getEnd());
	}

	AddressSetView findRange(String range) {
		String[] parts = range.split("-");
		AddressFactory addressFactory = currentProgram.getAddressFactory();
		Address start = addressFactory.getAddress(parts[0]);
		Address end = addressFactory.getAddress(parts[1]);
		return addressFactory.getAddressSet(start, end);
	}

	AddressSetView findSymbolsInFile(String pathname) throws Exception {
		AddressSet addressSet = new AddressSet();
		List<String> symbols = Files.readAllLines(Paths.get(pathname));
		symbols.forEach(symbol -> addressSet.add(findSymbol(symbol.strip())));
		return addressSet;
	}

	AddressSetView findSymbol(String name) {
		AddressSet addressSet = new AddressSet();
		SymbolTable symbolTable = currentProgram.getSymbolTable();

		for (Symbol symbol : symbolTable.getSymbols(name)) {
			FunctionManager functionManager = currentProgram.getFunctionManager();
			Function function = functionManager.getFunctionAt(symbol.getAddress());

			if (function != null) {
				addressSet.add(function.getBody());
			}
			else {
				Listing listing = currentProgram.getListing();
				CodeUnit codeUnit = listing.getCodeUnitAt(symbol.getAddress());
				AddressFactory addressFactory = currentProgram.getAddressFactory();
				addressSet.add(addressFactory.getAddressSet(codeUnit.getMinAddress(),
					codeUnit.getMaxAddress()));
			}
		}

		return addressSet;
	}

	Exporter findExporter(String name) {
		List<Exporter> exporters = new ArrayList(ClassSearcher.getInstances(Exporter.class));
		return exporters.stream().filter(e -> e.getName().equals(name)).findFirst().get();
	}

	List<Option> getOptions(Exporter exporter) {
		List<Option> options = new ArrayList<>(exporter.getOptions(() -> {
			return currentProgram;
		}));
		return options;
	}
}
