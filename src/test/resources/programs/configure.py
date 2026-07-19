#!/usr/bin/env python3

import argparse
from collections import Counter
import os
import pathlib
import sys


GNU_NOLIBC_BASE_CFLAGS = (
    "-gdwarf-4 -gctf -ffreestanding -fno-builtin -nostdinc -fno-pie -fno-pic "
    "-fno-asynchronous-unwind-tables -fno-unwind-tables"
)
GNU_NOLIBC_BASE_LDFLAGS = "-nostdlib -static -no-pie -Wl,--build-id=none -lgcc"
GNU_HOSTED_BASE_CFLAGS = "-gdwarf-4 -gctf"
GNU_HOSTED_BASE_LDFLAGS = "-Wl,--build-id=none"

GNU_NOLIBC_ARCHES = {
    "i686": {"tool_prefix": "i686-linux-gnu", "arch": "i686"},
    "x86_64": {"tool_prefix": "x86_64-linux-gnu", "arch": "x86_64"},
    "mips": {
        "tool_prefix": "mips-linux-gnu",
        "arch": "mips",
        "cflags": "-mno-check-zero-division -mno-abicalls -mno-shared",
    },
    "mipsel": {
        "tool_prefix": "mipsel-linux-gnu",
        "arch": "mipsel",
        "cflags": "-mno-check-zero-division -mno-abicalls -mno-shared",
    },
    "aarch64": {"tool_prefix": "aarch64-linux-gnu", "arch": "aarch64"},
    "arm": {"tool_prefix": "arm-linux-gnueabihf", "arch": "arm"},
    "mips64el": {
        "tool_prefix": "mips64el-linux-gnuabi64",
        "arch": "mips64el",
        "cflags": "-mno-check-zero-division -mno-abicalls -mno-shared",
    },
    "mips64": {
        "tool_prefix": "mips64-linux-gnuabi64",
        "arch": "mips64",
        "cflags": "-mno-check-zero-division -mno-abicalls -mno-shared",
    },
    "powerpc": {"tool_prefix": "powerpc-linux-gnu", "arch": "powerpc"},
    "powerpc64": {"tool_prefix": "powerpc64-linux-gnu", "arch": "powerpc64"},
    "powerpc64le": {
        "tool_prefix": "powerpc64le-linux-gnu",
        "arch": "powerpc64le",
    },
    "riscv64": {"tool_prefix": "riscv64-linux-gnu", "arch": "riscv64"},
    "s390x": {"tool_prefix": "s390x-linux-gnu", "arch": "s390x"},
}

GNU_HOSTED_ARCHES = {
    "aarch64": {"tool_prefix": "aarch64-linux-gnu", "arch": "aarch64"},
    "arm": {"tool_prefix": "arm-linux-gnueabihf", "arch": "arm"},
    "i686": {"tool_prefix": "i686-linux-gnu", "arch": "i686"},
    "x86_64": {"tool_prefix": "x86_64-linux-gnu", "arch": "x86_64"},
    "alpha": {"tool_prefix": "alpha-linux-gnu", "arch": "alpha"},
    "arc": {"tool_prefix": "arc-linux-gnu", "arch": "arc"},
    "m68k": {"tool_prefix": "m68k-linux-gnu", "arch": "m68k"},
    "mips": {
        "tool_prefix": "mips-linux-gnu",
        "arch": "mips",
        "cflags": "-mno-check-zero-division",
    },
    "mipsel": {
        "tool_prefix": "mipsel-linux-gnu",
        "arch": "mipsel",
        "cflags": "-mno-check-zero-division",
    },
    "mips64el": {
        "tool_prefix": "mips64el-linux-gnuabi64",
        "arch": "mips64el",
        "cflags": "-mno-check-zero-division",
    },
    "mips64": {
        "tool_prefix": "mips64-linux-gnuabi64",
        "arch": "mips64",
        "cflags": "-mno-check-zero-division",
    },
    "powerpc": {"tool_prefix": "powerpc-linux-gnu", "arch": "powerpc"},
    "powerpc64": {"tool_prefix": "powerpc64-linux-gnu", "arch": "powerpc64"},
    "powerpc64le": {
        "tool_prefix": "powerpc64le-linux-gnu",
        "arch": "powerpc64le",
    },
    "riscv64": {"tool_prefix": "riscv64-linux-gnu", "arch": "riscv64"},
    "s390x": {"tool_prefix": "s390x-linux-gnu", "arch": "s390x"},
    "sh4": {"tool_prefix": "sh4-linux-gnu", "arch": "sh4"},
    "sparc64": {"tool_prefix": "sparc64-linux-gnu", "arch": "sparc64"},
}


def norm(path: str) -> str:
    return pathlib.Path(path).as_posix()


def to_native(path: str) -> str:
    if os.name == "nt":
        return path.replace("/", "\\")
    return path


def quote_command(path: str) -> str:
    native_path = to_native(path)
    if any(char.isspace() for char in native_path):
        return f'"{native_path}"'
    return native_path


def shell_wrapper() -> tuple[str, str]:
    if os.name == "nt":
        return ("cmd /c", '"')
    return ("sh -c", "'")


def join_flags(*parts: str) -> str:
    return " ".join(part for part in parts if part)


def output_name(build_path: str, colliding_stems: set[str]) -> str:
    stem = pathlib.Path(build_path).stem
    if stem not in colliding_stems:
        return stem
    return pathlib.Path(build_path).with_suffix("").as_posix().replace("/", "__")


def collect_colliding_stems(source_build_paths: list[str]) -> set[str]:
    stem_counts = Counter(pathlib.Path(build).stem for build in source_build_paths)
    return {stem for stem, count in stem_counts.items() if count > 1}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="configure.py",
        description="Generate a multi-target Ninja build for test resource fixtures",
    )
    parser.add_argument(
        "srcpath",
        nargs="?",
        default=".",
        help="Fixture root path (default: current directory)",
    )
    parser.add_argument(
        "--name",
        default=None,
        help="Fixture output base name (default: fixture directory name)",
    )
    parser.add_argument(
        "--sources",
        nargs="+",
        required=True,
        help="Source files relative to srcpath, e.g. src/main.c src/allocator.c",
    )
    parser.add_argument(
        "--include",
        action="append",
        default=[],
        help="Include directories relative to srcpath (can be repeated)",
    )
    parser.add_argument(
        "--targets",
        default="all",
        help="Comma-separated target ids, or all",
    )
    parser.add_argument(
        "--ninja-file",
        default="build.ninja",
        help="Output Ninja filename (default: build.ninja)",
    )
    parser.add_argument(
        "--with-linux-nolibc",
        action="store_true",
        help="Enable ELF/Linux/nolibc targets",
    )
    parser.add_argument(
        "--with-windows-msvc",
        action="store_true",
        help="Enable COFF/Windows/MSVC targets",
    )
    parser.add_argument(
        "--with-windows-borland",
        action="store_true",
        help="Enable OMF/Windows/Borland targets",
    )
    parser.add_argument(
        "--with-linux-gnu",
        action="store_true",
        help="Enable ELF/Linux/GNU targets with hosted C library",
    )
    parser.add_argument(
        "--nolibc",
        default=os.environ.get("NOLIBC"),
        help="Path to nolibc headers root",
    )
    parser.add_argument("--msvc-cl-x86", default=os.environ.get("MSVC_CL_X86", "cl"))
    parser.add_argument("--msvc-cl-x64", default=os.environ.get("MSVC_CL_X64", "cl"))
    parser.add_argument("--msvc-cl-arm", default=os.environ.get("MSVC_CL_ARM", "cl"))
    parser.add_argument("--msvc-cl-arm64", default=os.environ.get("MSVC_CL_ARM64", "cl"))
    parser.add_argument("--msvc-link", default=os.environ.get("MSVC_LINK", "link"))
    parser.add_argument("--dumpbin", default=os.environ.get("DUMPBIN", "dumpbin"))
    parser.add_argument("--bcc32", default=os.environ.get("BCC32", "bcc32"))
    parser.add_argument("--tdump", default=os.environ.get("TDUMP", "tdump"))
    return parser


def resolve_msvc_tool(configured: str, tool_name: str, target_arch: str | None = None) -> str:
    if configured != tool_name or os.name != "nt":
        return configured

    roots = []
    vc_tools = os.environ.get("VCToolsInstallDir")
    if vc_tools:
        roots.append(vc_tools)

    tools_root = r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC"
    if os.path.isdir(tools_root):
        versions = sorted(
            [entry.name for entry in os.scandir(tools_root) if entry.is_dir()],
            reverse=True,
        )
        roots.extend([os.path.join(tools_root, version) for version in versions])

    seen = set()
    for root in roots:
        normalized = os.path.normcase(os.path.normpath(root))
        if normalized in seen:
            continue
        seen.add(normalized)
        arch = target_arch or "x64"
        candidate = os.path.join(root, "bin", "Hostx64", arch, f"{tool_name}.exe")
        if os.path.exists(candidate):
            return quote_command(candidate)
    return configured


def has_target_specific_msvc_cl(command: str) -> bool:
    return command.strip().strip('"').lower() != "cl"


def find_windows_sdk_libpaths(target_arch: str) -> list[str]:
    if os.name != "nt":
        return []

    sdk_root = r"C:\Program Files (x86)\Windows Kits\10\Lib"
    if not os.path.isdir(sdk_root):
        return []

    versions = sorted(
        [entry.name for entry in os.scandir(sdk_root) if entry.is_dir()],
        reverse=True,
    )
    for version in versions:
        um_path = os.path.join(sdk_root, version, "um", target_arch)
        ucrt_path = os.path.join(sdk_root, version, "ucrt", target_arch)
        if os.path.exists(os.path.join(um_path, "kernel32.lib")) and os.path.isdir(ucrt_path):
            return [norm(um_path), norm(ucrt_path)]
    return []


def make_gnu_target(
    platform: str,
    target_arch: str,
    tool_prefix: str,
    family_enabled: bool,
    cflags: str = "",
) -> dict[str, str | bool]:
    base_cflags = GNU_NOLIBC_BASE_CFLAGS if platform == "linux-nolibc" else GNU_HOSTED_BASE_CFLAGS
    base_ldflags = GNU_NOLIBC_BASE_LDFLAGS if platform == "linux-nolibc" else GNU_HOSTED_BASE_LDFLAGS
    return {
        "enabled": family_enabled,
        "format": "elf",
        "platform": platform,
        "arch": target_arch,
        "family": "gnu",
        "cc": f"{tool_prefix}-gcc",
        "ld": f"{tool_prefix}-gcc",
        "objdump": f"{tool_prefix}-objdump",
        "cflags": join_flags(base_cflags, cflags),
        "ldflags": base_ldflags,
    }


def make_msvc_target(target_arch: str, compiler: str, family_enabled: bool, args) -> dict[str, str | bool]:
    return {
        "enabled": family_enabled and has_target_specific_msvc_cl(compiler),
        "format": "coff",
        "platform": "windows-msvc",
        "arch": target_arch,
        "family": "msvc",
        "cc": compiler,
        "link": args.msvc_link,
        "dumpbin": args.dumpbin,
        "cflags": "/TC /Zi /Od /nologo",
        "ldflags": "/nologo",
    }


def build_targets(args, selected_families: set[str]) -> dict[str, dict[str, str | bool]]:
    def family_enabled(platform_name: str) -> bool:
        if not selected_families:
            return True
        return platform_name in selected_families

    built_targets = {}

    for target_id, spec in GNU_NOLIBC_ARCHES.items():
        built_targets[f"{target_id}-linux-nolibc-gnu"] = make_gnu_target(
            "linux-nolibc",
            spec["arch"],
            spec["tool_prefix"],
            family_enabled("linux-nolibc"),
            spec.get("cflags", ""),
        )

    for target_id, spec in GNU_HOSTED_ARCHES.items():
        built_targets[f"{target_id}-linux-gnu-gnu"] = make_gnu_target(
            "linux-gnu",
            spec["arch"],
            spec["tool_prefix"],
            family_enabled("linux-gnu"),
            spec.get("cflags", ""),
        )

    msvc_enabled = family_enabled("windows-msvc")
    built_targets["i686-windows-msvc-coff"] = make_msvc_target("x86", args.msvc_cl_x86, msvc_enabled, args)
    built_targets["x86_64-windows-msvc-coff"] = make_msvc_target("x64", args.msvc_cl_x64, msvc_enabled, args)
    built_targets["arm-windows-msvc-coff"] = make_msvc_target("arm", args.msvc_cl_arm, msvc_enabled, args)
    built_targets["arm64-windows-msvc-coff"] = make_msvc_target("arm64", args.msvc_cl_arm64, msvc_enabled, args)

    built_targets["i686-windows-borland-omf"] = {
        "enabled": family_enabled("windows-borland"),
        "format": "omf",
        "platform": "windows-borland",
        "arch": "x86",
        "family": "borland",
        "cc": args.bcc32,
        "tdump": args.tdump,
        "cflags": "-v -Od -M",
        "ldflags": "",
    }

    return built_targets


def select_target_ids(
    requested_targets: str,
    targets: dict[str, dict[str, str | bool]],
    selected_families: set[str],
) -> list[str]:
    if requested_targets == "all":
        return [target_id for target_id, spec in targets.items() if spec["enabled"]]

    selected_ids = []
    for target_id in [item.strip() for item in requested_targets.split(",") if item.strip()]:
        if target_id not in targets:
            raise SystemExit(f"Unknown target id: {target_id}")
        if selected_families and not targets[target_id]["enabled"]:
            raise SystemExit(f"Target filtered out by --with-* switches: {target_id}")
        selected_ids.append(target_id)
    return selected_ids


def target_outdir(output_dir: str, spec: dict[str, str | bool]) -> str:
    outdir_unix = (
        pathlib.Path(output_dir)
        .joinpath("reference", spec["format"], spec["platform"], spec["arch"])
        .resolve()
        .as_posix()
    )
    return to_native(outdir_unix)


def emit_target_header(fp, target_id: str, spec: dict[str, str | bool], outdir: str, ensure_stamp: str) -> None:
    fp.write(f"# {target_id}\n")
    fp.write(f"{target_id}_outdir = {outdir}\n")
    fp.write(
        f"{target_id}_cflags = {spec['cflags']} {os.environ.get('CFLAGS', '')} {os.environ.get(target_id + '_CFLAGS', '')}\n"
    )
    fp.write(
        f"{target_id}_ldflags = {spec['ldflags']} {os.environ.get('LDFLAGS', '')} {os.environ.get(target_id + '_LDFLAGS', '')}\n"
    )
    fp.write(f"build {ensure_stamp}: ensure_dir\n")
    fp.write(f"  dir = ${{{target_id}_outdir}}\n\n")


def gnu_include_flags(
    spec: dict[str, str | bool],
    include_flags_gnu: str,
    nolibc_include_dir: str | None,
    linux_tools_include_dir: str | None,
) -> str:
    flags = [include_flags_gnu]
    if spec["platform"] == "linux-nolibc":
        flags.append(f"-I{linux_tools_include_dir}")
        flags.append(f"-I{nolibc_include_dir}")
        flags.append(f"-isystem /usr/include/$$({spec['cc']} -dumpmachine)")
        flags.append(f"-isystem /usr/$$({spec['cc']} -dumpmachine)/include")
        flags.append(f"-isystem $$({spec['cc']} -print-sysroot)/usr/include")
        flags.append(f"-isystem $$({spec['cc']} -print-file-name=include)")
    return join_flags(*flags)


def emit_gnu_target(
    fp,
    target_id: str,
    spec: dict[str, str | bool],
    source_build_paths: list[str],
    source_output_names: dict[str, str],
    fixture_name: str,
    path_sep: str,
    include_flags_gnu: str,
    nolibc_include_dir: str | None,
    linux_tools_include_dir: str | None,
    output_dir: str,
) -> tuple[list[str], str]:
    outdir = target_outdir(output_dir, spec)
    ensure_stamp = f"${{{target_id}_outdir}}{path_sep}.dir.stamp"
    emit_target_header(fp, target_id, spec, outdir, ensure_stamp)

    include_flags = gnu_include_flags(spec, include_flags_gnu, nolibc_include_dir, linux_tools_include_dir)
    fp.write(f"rule {target_id}_cc_obj\n")
    fp.write(f"  command = {spec['cc']} ${{{target_id}_cflags}} {include_flags} -c $in -o $out\n")
    fp.write(f"rule {target_id}_cc_asm\n")
    fp.write(f"  command = {spec['cc']} ${{{target_id}_cflags}} {include_flags} -S -c $in -o $out\n")
    fp.write(f"rule {target_id}_objdump\n")
    fp.write(f"  command = {spec['objdump']} -x $in > $out\n")
    fp.write(f"rule {target_id}_combine\n")
    fp.write(f"  command = {spec['cc']} -r $in -o $out\n")
    fp.write(f"rule {target_id}_link\n")
    fp.write(f"  command = {spec['ld']} $in -o $out ${{{target_id}_ldflags}}\n\n")

    objs = []
    asms = []
    dumps = []
    for build in source_build_paths:
        name = source_output_names[build]
        obj = f"${{{target_id}_outdir}}{path_sep}{name}.o"
        asm = f"${{{target_id}_outdir}}{path_sep}{name}.s"
        dump = f"${{{target_id}_outdir}}{path_sep}{name}.txt"
        fp.write(f"build {obj}: {target_id}_cc_obj {build} || {ensure_stamp}\n")
        fp.write(f"build {asm}: {target_id}_cc_asm {build} || {ensure_stamp}\n")
        fp.write(f"build {dump}: {target_id}_objdump {obj} || {ensure_stamp}\n")
        objs.append(obj)
        asms.append(asm)
        dumps.append(dump)

    combined = f"${{{target_id}_outdir}}{path_sep}{fixture_name}.o"
    final = f"${{{target_id}_outdir}}{path_sep}{fixture_name}.elf"
    fp.write(f"build {combined}: {target_id}_combine {' '.join(objs)} || {ensure_stamp}\n")
    fp.write(f"build {final}: {target_id}_link {combined} || {ensure_stamp}\n")
    fp.write(f"build {target_id}: phony {' '.join([final] + asms + dumps)}\n\n")
    return [final] + asms + dumps, final


def emit_msvc_target(
    fp,
    target_id: str,
    spec: dict[str, str | bool],
    source_build_paths: list[str],
    source_output_names: dict[str, str],
    fixture_name: str,
    path_sep: str,
    include_flags_msvc: str,
    output_dir: str,
) -> tuple[list[str], str]:
    outdir = target_outdir(output_dir, spec)
    ensure_stamp = f"${{{target_id}_outdir}}{path_sep}.dir.stamp"
    emit_target_header(fp, target_id, spec, outdir, ensure_stamp)

    machine_flag = {
        "x86": "/MACHINE:X86",
        "x64": "/MACHINE:X64",
        "arm": "/MACHINE:ARM",
        "arm64": "/MACHINE:ARM64",
    }.get(spec["arch"], "")
    sdk_libpath_flags = " ".join(
        f"/LIBPATH:{quote_command(path)}" for path in find_windows_sdk_libpaths(spec["arch"])
    )
    shell_cmd, shell_quote = shell_wrapper()

    fp.write(f"rule {target_id}_cc\n")
    fp.write(
        f"  command = {spec['cc']} ${{{target_id}_cflags}} {include_flags_msvc} /FS /Fd${{outdir}}{path_sep}${{obj_name}}.pdb /c $in /Fo${{outdir}}{path_sep}${{obj_name}}.obj /Fa${{outdir}}{path_sep}${{obj_name}}.asm\n"
    )
    fp.write(f"rule {target_id}_dumpbin\n")
    fp.write(f"  command = {shell_cmd} {shell_quote}{spec['dumpbin']} /nologo /all $in > $out{shell_quote}\n")
    fp.write(f"rule {target_id}_link\n")
    fp.write(
        f"  command = {spec['link']} /nologo {machine_flag} /OUT:${{exe}} /DEBUG /PDB:${{pdb}} {sdk_libpath_flags} ${{{target_id}_ldflags}} $in\n\n"
    )

    objs = []
    asms = []
    dumps = []
    for build in source_build_paths:
        name = source_output_names[build]
        obj = f"${{{target_id}_outdir}}{path_sep}{name}.obj"
        asm = f"${{{target_id}_outdir}}{path_sep}{name}.asm"
        dump = f"${{{target_id}_outdir}}{path_sep}{name}.txt"
        fp.write(f"build {obj} {asm}: {target_id}_cc {build} || {ensure_stamp}\n")
        fp.write(f"  obj_name = {name}\n")
        fp.write(f"  outdir = ${{{target_id}_outdir}}\n")
        fp.write(f"build {dump}: {target_id}_dumpbin {obj} || {ensure_stamp}\n")
        objs.append(obj)
        asms.append(asm)
        dumps.append(dump)

    exe_out = f"${{{target_id}_outdir}}{path_sep}{fixture_name}.exe"
    exe_pdb = f"${{{target_id}_outdir}}{path_sep}{fixture_name}.pdb"
    exe_dump = f"${{{target_id}_outdir}}{path_sep}{fixture_name}.exe.txt"
    fp.write(f"build {exe_out} {exe_pdb}: {target_id}_link {' '.join(objs)} || {ensure_stamp}\n")
    fp.write(f"  exe = {exe_out}\n")
    fp.write(f"  pdb = {exe_pdb}\n")
    fp.write(f"build {exe_dump}: {target_id}_dumpbin {exe_out} || {ensure_stamp}\n")
    fp.write(f"build {target_id}: phony {' '.join([exe_out, exe_pdb, exe_dump] + asms + dumps)}\n\n")
    return [exe_out, exe_pdb, exe_dump] + asms + dumps, exe_out


def emit_borland_target(
    fp,
    target_id: str,
    spec: dict[str, str | bool],
    source_build_paths: list[str],
    source_output_names: dict[str, str],
    fixture_name: str,
    path_sep: str,
    include_flags_borland: str,
    output_dir: str,
) -> tuple[list[str], str]:
    outdir = target_outdir(output_dir, spec)
    ensure_stamp = f"${{{target_id}_outdir}}{path_sep}.dir.stamp"
    emit_target_header(fp, target_id, spec, outdir, ensure_stamp)

    shell_cmd, shell_quote = shell_wrapper()
    if os.name == "nt":
        cc_move = "move /Y ${source_stem}.obj ${outobj}"
        asm_move = "move /Y ${source_stem}.asm ${outasm}"
    else:
        cc_move = "mv ${source_stem}.obj ${outobj}"
        asm_move = "mv ${source_stem}.asm ${outasm}"

    fp.write(f"rule {target_id}_cc\n")
    fp.write(
        f"  command = {shell_cmd} {shell_quote}{spec['cc']} -c ${{{target_id}_cflags}} {include_flags_borland} $in && {cc_move}{shell_quote}\n"
    )
    fp.write(f"rule {target_id}_cc_asm\n")
    fp.write(
        f"  command = {shell_cmd} {shell_quote}{spec['cc']} -S -c ${{{target_id}_cflags}} {include_flags_borland} $in && {asm_move}{shell_quote}\n"
    )
    fp.write(f"rule {target_id}_link\n")
    fp.write(f"  command = {spec['cc']} ${{{target_id}_cflags}} -e$out $in\n")
    fp.write(f"rule {target_id}_tdump\n")
    fp.write(f"  command = {spec['tdump']} $in > $out\n\n")

    objs = []
    asms = []
    dumps = []
    for build in source_build_paths:
        name = source_output_names[build]
        obj = f"${{{target_id}_outdir}}{path_sep}{name}.obj"
        asm = f"${{{target_id}_outdir}}{path_sep}{name}.asm"
        dump = f"${{{target_id}_outdir}}{path_sep}{name}.txt"
        fp.write(f"build {obj}: {target_id}_cc {build} || {ensure_stamp}\n")
        fp.write(f"  source_stem = {name}\n")
        fp.write(f"  outobj = ${{{target_id}_outdir}}{path_sep}{name}.obj\n")
        fp.write(f"build {asm}: {target_id}_cc_asm {build} || {ensure_stamp}\n")
        fp.write(f"  source_stem = {name}\n")
        fp.write(f"  outasm = ${{{target_id}_outdir}}{path_sep}{name}.asm\n")
        fp.write(f"build {dump}: {target_id}_tdump {obj} || {ensure_stamp}\n")
        objs.append(obj)
        asms.append(asm)
        dumps.append(dump)

    exe_out = f"${{{target_id}_outdir}}{path_sep}{fixture_name}.exe"
    fp.write(f"build {exe_out}: {target_id}_link {' '.join(objs)} || {ensure_stamp}\n")
    fp.write(f"build {target_id}: phony {' '.join([exe_out] + asms + dumps)}\n\n")
    return [exe_out] + asms + dumps, exe_out


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    args.msvc_cl_x86 = resolve_msvc_tool(args.msvc_cl_x86, "cl", "x86")
    args.msvc_cl_x64 = resolve_msvc_tool(args.msvc_cl_x64, "cl", "x64")
    args.msvc_cl_arm = resolve_msvc_tool(args.msvc_cl_arm, "cl", "arm")
    args.msvc_cl_arm64 = resolve_msvc_tool(args.msvc_cl_arm64, "cl", "arm64")
    args.msvc_link = resolve_msvc_tool(args.msvc_link, "link")
    args.dumpbin = resolve_msvc_tool(args.dumpbin, "dumpbin")

    fixture_dir = os.path.realpath(args.srcpath)
    output_dir = fixture_dir
    fixture_name = args.name or os.path.basename(fixture_dir)
    include_dirs = [norm(os.path.join(fixture_dir, include_dir)) for include_dir in args.include]

    if args.with_linux_nolibc and not args.nolibc:
        default_nolibc = "/home/boricj/Documents/linux/tools/include/nolibc"
        if os.path.isdir(default_nolibc):
            args.nolibc = default_nolibc

    nolibc_include_dir = norm(args.nolibc) if args.nolibc else None
    linux_tools_include_dir = None
    if nolibc_include_dir:
        linux_tools_include_dir = norm(pathlib.Path(nolibc_include_dir).parent.as_posix())
    if args.with_linux_nolibc and not nolibc_include_dir:
        raise SystemExit(
            "linux-nolibc targets require --nolibc or NOLIBC to point to a Linux tools/include/nolibc directory"
        )

    selected_families = set()
    if args.with_linux_nolibc:
        selected_families.add("linux-nolibc")
    if args.with_linux_gnu:
        selected_families.add("linux-gnu")
    if args.with_windows_msvc:
        selected_families.add("windows-msvc")
    if args.with_windows_borland:
        selected_families.add("windows-borland")

    targets = build_targets(args, selected_families)
    selected_ids = select_target_ids(args.targets, targets, selected_families)
    if not selected_ids:
        raise SystemExit("No targets selected")

    source_abs_paths = [norm(os.path.join(fixture_dir, src)) for src in args.sources]
    source_build_paths = []
    for abs_path in source_abs_paths:
        try:
            source_build_paths.append(norm(os.path.relpath(abs_path, fixture_dir)))
        except ValueError:
            source_build_paths.append(abs_path)

    colliding_stems = collect_colliding_stems(source_build_paths)
    if colliding_stems and any(targets[target_id]["family"] == "borland" for target_id in selected_ids):
        collisions = ", ".join(sorted(colliding_stems))
        raise SystemExit(
            "Borland targets cannot safely build duplicate source stems in one fixture: "
            f"{collisions}. Rename files or disable --with-windows-borland."
        )
    source_output_names = {
        build: output_name(build, colliding_stems) for build in source_build_paths
    }

    path_sep = "\\" if os.name == "nt" else "/"
    include_flags_gnu = " ".join(f"-I{include_dir}" for include_dir in include_dirs)
    include_flags_msvc = " ".join(f"/I{include_dir}" for include_dir in include_dirs)
    include_flags_borland = " ".join(f"-I{include_dir}" for include_dir in include_dirs)
    if os.path.isabs(args.ninja_file):
        ninja_path = args.ninja_file
    else:
        ninja_path = os.path.join(output_dir, args.ninja_file)
    ninja_dir = os.path.dirname(ninja_path)
    if ninja_dir:
        os.makedirs(ninja_dir, exist_ok=True)

    with open(ninja_path, "w", encoding="utf-8") as fp:
        fp.write("ninja_required_version = 1.7\n\n")
        fp.write("rule ensure_dir\n")
        fp.write(
            f"  command = {quote_command(sys.executable)} -c \"import os,sys; os.makedirs(sys.argv[1], exist_ok=True); open(sys.argv[2], 'a').close()\" \"$dir\" \"$out\"\n\n"
        )

        all_outputs = []
        family_outputs = {"elf": [], "coff": [], "omf": []}

        for target_id in selected_ids:
            spec = targets[target_id]
            if spec["family"] == "gnu":
                emitted_outputs, family_output = emit_gnu_target(
                    fp,
                    target_id,
                    spec,
                    source_build_paths,
                    source_output_names,
                    fixture_name,
                    path_sep,
                    include_flags_gnu,
                    nolibc_include_dir,
                    linux_tools_include_dir,
                    output_dir,
                )
                family_key = "elf"
            elif spec["family"] == "msvc":
                emitted_outputs, family_output = emit_msvc_target(
                    fp,
                    target_id,
                    spec,
                    source_build_paths,
                    source_output_names,
                    fixture_name,
                    path_sep,
                    include_flags_msvc,
                    output_dir,
                )
                family_key = "coff"
            else:
                emitted_outputs, family_output = emit_borland_target(
                    fp,
                    target_id,
                    spec,
                    source_build_paths,
                    source_output_names,
                    fixture_name,
                    path_sep,
                    include_flags_borland,
                    output_dir,
                )
                family_key = "omf"

            all_outputs.extend(emitted_outputs)
            family_outputs[family_key].append(family_output)

        if family_outputs["elf"]:
            fp.write(f"build elf-all: phony {' '.join(family_outputs['elf'])}\n")
        if family_outputs["coff"]:
            fp.write(f"build coff-all: phony {' '.join(family_outputs['coff'])}\n")
        if family_outputs["omf"]:
            fp.write(f"build omf-all: phony {' '.join(family_outputs['omf'])}\n")

        fp.write(f"build all: phony {' '.join(all_outputs)}\n")
        fp.write("default all\n")

    print(f"Wrote {ninja_path}")
    run_dir = os.path.dirname(ninja_path) or output_dir
    ninja_name = os.path.basename(ninja_path)
    if ninja_name == "build.ninja":
        print(f"Run: cd {to_native(run_dir)} && ninja [target]")
    else:
        print(f"Run: cd {to_native(run_dir)} && ninja -f {ninja_name} [target]")
    print("Targets:")
    for target_id in selected_ids:
        spec = targets[target_id]
        out = os.path.join("reference", spec["format"], spec["platform"], spec["arch"])
        print(f"  - {target_id} -> {out}")


if __name__ == "__main__":
    main()