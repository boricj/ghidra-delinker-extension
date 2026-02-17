# Object file exporter extension for Ghidra

This Ghidra extension enables exporting parts of a program as object files. These object files have valid metadata (symbols, relocation tables…) and as such can be reused directly by a toolchain for further processing.

Use-cases include:

 * [Advanced binary patching](https://boricj.net/tenchu1/2024/05/31/part-11.html), by leveraging the linker to mend both original and modified parts together instead of doing this work by hand ;
 * [Software ports](https://boricj.net/atari-jaguar-sdk/2024/01/02/part-5.html), by isolating system-independent code from a program and replacing the rest ;
 * Converting [programs](https://boricj.net/atari-jaguar-sdk/2023/12/18/part-3.html) or object files from one file format to another ;
 * [Creating](https://boricj.net/tenchu1/2024/03/11/part-5.html) [libraries](https://boricj.net/tenchu1/2024/03/18/part-6.html), by extracting parts of a program and reusing them in another context ;
 * Decompilation projects, by splitting a program into multiple object files and reimplementing these _Ship of Theseus_-style ;
 * …

Matrix of supported instruction set architectures and object files:

|               | x86/x86_64 | MIPS |
| ------------- | ---------- | ---- |
| COFF          | ✅         | ❌   |
| ELF           | ✅         | ✅   |

## Building (CLI)

 * Clone this repository ;
 * Define the `GHIDRA_INSTALL_DIR` environment variable to point to your Ghidra installation directory ;
 * Run `gradle buildExtension`.

The Ghidra extension archive will be created inside the `dist/` directory.

> [!NOTE]
> GitHub Maven repositories require	authentication to download packages, you must either:
>
> * Create a GitHub classic token with the `read:packages` right, then add `githubToken=ghp_xxx` to `${GRADLE_USER_HOME}/gradle.properties` (usually defaults to `~/.gradle/gradle.properties`).
> * Run `gradle installStandaloneDeps` to build and install vendored dependencies from submodules.

## Installation

 * Download the extension from the [releases page](https://github.com/boricj/ghidra-delinker-extension/releases) or build it locally ;
 * Install the extension in your Ghidra instance with `File > Install Extensions…` ;
 * Enable the `RelocationTableSynthesizedPlugin` plugin with `File > Configure > Experimental` inside a CodeBrowser window.

## Usage 

 1. Select a set of addresses in the Listing view ;
 2. Run the `Relocation table synthesizer` analyzer (available in one-shot mode) ;
 3. Invoke a relocatable object file exporter with `File > Export Program…`

The reconstructed relocations can be viewed with `Window > Relocation table (synthesized)`.

 * ⚠️ The _relocation table synthesizer_ analyzer relies on a fully populated Ghidra database (with correctly declared symbols, data types and references) in order to work. **Incorrect or missing information may lead to broken or undiscovered relocations** during the analysis.
 * ⚠️ The object file exporters rely on the results of the _relocation table synthesizer_ analyzer in order to work. When in doubt, **run this analyzer right before exporting an object file** to make sure the relocation table contents are up-to-date with the current state of the program.

## How does it work?

Object files are made of three parts:

 * Relocatable section bytes ;
 * A symbol table ;
 * A relocation table.

When a linker is invoked to generate an executable from a bunch of object files, it will:
 * Lay out their sections in memory ;
 * Compute the addresses of the symbols in the virtual address space ;
 * Apply the relocations based on the final addresses of the symbols onto the section bytes.

Normally the relocation table is discarded after this process, as well as the symbol table if debugging symbols aren't kept, leaving only the un-relocatable section bytes.
However, through careful analysis this data can be recreated, which allows us to then effectively _delink_ the program back into object files.
