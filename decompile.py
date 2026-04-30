#!/usr/bin/env python3
"""Unified decompilation wrapper — runs inside Docker container.

Detects file type via magic bytes and routes to the appropriate decompiler:
  - ELF / native PE / COFF / ar archive → Ghidra headless (fallback: RetDec)
  - .NET DLL/EXE     → ILSpy CLI
  - JAR / .class     → CFR

Output naming by file type:
  - ELF / native PE / COFF / ar → <name>.cpp
  - .NET DLL/EXE     → <name>.cs
  - JAR / .class     → <name>.java
  If file already exists, insert date: <name>.YYYYMMDD.<ext>
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import struct
import tempfile
from datetime import datetime
from pathlib import Path

GHIDRA_DIR = os.environ.get("GHIDRA_DIR", "/opt/ghidra")
CFR_JAR = "/opt/cfr.jar"
ILSPYCMD = shutil.which("ilspy-cli") or "/opt/ilspy-cli/ilspy-cli"
RETDEC = shutil.which("retdec-decompiler") or ""

DEFAULT_OUTPUT_DIR = "/data/decompiled"
GHIDRA_TIMEOUT = 1800  # 30 minutes for large binaries


# ── File type detection ──────────────────────────────────────────────

def read_magic(path, n=8):
    with open(path, "rb") as f:
        return f.read(n)


def detect_type(path):
    """Return one of: 'elf', 'pe_native', 'dotnet', 'coff', 'ar_archive', 'jar', 'class', 'unknown'."""
    magic = read_magic(path, 8)

    # ELF (includes .o, .so, executables)
    if magic[:4] == b"\x7fELF":
        return "elf"

    # Java .class
    if magic[:4] == b"\xca\xfe\xba\xbe":
        return "class"

    # ZIP-based (JAR / APK)
    if magic[:4] == b"PK\x03\x04":
        try:
            result = subprocess.run(
                ["python3", "-c",
                 f"import zipfile; z=zipfile.ZipFile('{path}'); "
                 f"print(any('META-INF/MANIFEST.MF' in n.upper() for n in z.namelist()))"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip() == "True":
                return "jar"
        except Exception:
            pass
        return "jar"

    # ar archive (.a static lib, .lib import lib)
    if magic[:8] == b"!<arch>\n":
        return "ar_archive"

    # COFF object file (.o for Windows, machine type in first 2 bytes)
    # 0x014c = i386, 0x8664 = AMD64, 0x01c0 = ARM, 0xaa64 = ARM64
    if len(magic) >= 2:
        machine = struct.unpack("<H", magic[:2])[0]
        if machine in (0x014c, 0x8664, 0x01c0, 0xaa64):
            return "coff"

    # PE (MZ header)
    if magic[:2] == b"MZ":
        try:
            with open(path, "rb") as f:
                f.seek(0x3C)
                pe_offset = struct.unpack("<I", f.read(4))[0]
                f.seek(pe_offset)
                pe_sig = f.read(4)
                if pe_sig != b"PE\x00\x00":
                    return "pe_native"
                f.seek(pe_offset + 24)
                opt_magic = struct.unpack("<H", f.read(2))[0]
                if opt_magic == 0x10b:
                    f.seek(pe_offset + 24 + 96)
                elif opt_magic == 0x20b:
                    f.seek(pe_offset + 24 + 112)
                else:
                    return "pe_native"
                f.read(14 * 8)
                clr_rva = struct.unpack("<I", f.read(4))[0]
                return "dotnet" if clr_rva != 0 else "pe_native"
        except Exception:
            return "pe_native"

    return "unknown"


# ── Output path helper ───────────────────────────────────────────────

TYPE_EXT_MAP = {
    "elf": ".cpp",
    "pe_native": ".cpp",
    "coff": ".cpp",
    "ar_archive": ".cpp",
    "dotnet": ".cs",
    "jar": ".java",
    "class": ".java",
}


def output_path_for(input_path, output_dir, file_type):
    """Return output path: <name>.<ext> or <name>.YYYYMMDD.<ext> if exists."""
    basename = Path(input_path).name
    ext = TYPE_EXT_MAP.get(file_type, ".cpp")
    out_path = os.path.join(output_dir, basename + ext)
    if not os.path.exists(out_path):
        return out_path
    date_str = datetime.now().strftime("%Y%m%d")
    out_path = os.path.join(output_dir, f"{basename}.{date_str}{ext}")
    return out_path


# ── ar archive extraction ────────────────────────────────────────────

def is_import_stub(path):
    """Check if an object file is an import stub (jmp *[IAT], no real code).

    Detects two forms:
    1. COFF short import object (sig 0x0000 0xFFFF)
    2. Regular COFF/ELF .o with only jmp *[0x0] in .text (import library member)
    """
    # Form 1: COFF short import object
    try:
        with open(path, "rb") as f:
            sig1, sig2 = struct.unpack("<HH", f.read(4))
        if sig1 == 0x0000 and sig2 == 0xFFFF:
            return True
    except Exception:
        pass

    # Form 2: Check via objdump if .text only has indirect jump stubs
    try:
        result = subprocess.run(
            ["objdump", "-d", path],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            # Look for actual instruction lines (indented, after <symbol>:)
            instr_lines = [l for l in lines if l and l[0] == ' ' and ':' in l]
            if not instr_lines:
                return True
            # If all instructions are jmp *[0x0] or nop, it's an import stub
            for line in instr_lines:
                code = line.split('\t')[-1].strip() if '\t' in line else ""
                if code and code not in ("jmp", "nop", "xchg", "ret"):
                    # Has a real instruction → not a stub
                    if "jmp" not in code or "*0x0" not in code:
                        return False
            return True
    except Exception:
        pass
    return False


def get_archive_symbols(archive_path):
    """Use nm to list all symbols from an archive."""
    try:
        result = subprocess.run(
            ["nm", "--defined-only", archive_path],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            # Try objdump as fallback
            result = subprocess.run(
                ["objdump", "-t", archive_path],
                capture_output=True, text=True, timeout=30
            )
        if result.returncode == 0:
            symbols = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    sym = parts[-1]
                    if sym and not sym.startswith('.') and sym != 'archive':
                        symbols.append(sym)
            return symbols
    except Exception:
        pass
    return []


def parse_coff_import_symbols(path):
    """Parse COFF import object, return (dll_name, [symbol_names])."""
    try:
        with open(path, "rb") as f:
            data = f.read()
        if len(data) < 20:
            return None, []
        size_of_data = struct.unpack("<I", data[12:16])[0]
        strings = data[20:20 + size_of_data]
        parts = strings.split(b'\x00')
        names = [p.decode('ascii', errors='replace') for p in parts if p]
        dll_name = names[0] if names else "unknown"
        symbols = names[1:]
        return dll_name, symbols
    except Exception:
        return None, []


def objdump_disassemble(path):
    """Get objdump disassembly output for an object file."""
    try:
        result = subprocess.run(
            ["objdump", "-d", "-C", path],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            return result.stdout
    except Exception:
        pass
    return None


def extract_ar_archive(archive_path):
    """Extract ar archive to a temp dir, return list of member file paths."""
    tmp_dir = tempfile.mkdtemp(prefix="ar_extract_")
    # ar x may fail if members have subdirectory paths (e.g. tmp32/gost_sign.obj)
    # First try plain extraction, then try with mkdir for each member
    result = subprocess.run(
        ["ar", "x", archive_path],
        cwd=tmp_dir, capture_output=True, text=True, timeout=120
    )
    if result.returncode != 0:
        # List members and create subdirs before extracting
        try:
            list_result = subprocess.run(
                ["ar", "t", archive_path],
                capture_output=True, text=True, timeout=30
            )
            if list_result.returncode == 0:
                for member_name in list_result.stdout.splitlines():
                    member_name = member_name.strip()
                    if '/' in member_name:
                        subdir = os.path.join(tmp_dir, os.path.dirname(member_name))
                        os.makedirs(subdir, exist_ok=True)
                result = subprocess.run(
                    ["ar", "x", archive_path],
                    cwd=tmp_dir, capture_output=True, text=True, timeout=120
                )
        except Exception:
            pass
    if result.returncode != 0:
        print(f"[ar] Failed to extract {archive_path}: {result.stderr}", file=sys.stderr)
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return []
    members = []
    for root, dirs, files in os.walk(tmp_dir):
        for f in files:
            members.append(os.path.join(root, f))
    return members, tmp_dir


# ── Decompilers ──────────────────────────────────────────────────────

def decompile_ghidra(input_path, output_dir, file_type):
    """Decompile ELF, native PE, COFF, or ar archive using Ghidra headless."""
    # For ar archives, extract and decompile each member, then concatenate
    if file_type == "ar_archive":
        return decompile_ar_archive(input_path, output_dir)

    out_path = output_path_for(input_path, output_dir, file_type)
    os.makedirs(output_dir, exist_ok=True)

    tmp_out = os.path.join("/tmp", "ghidra_out.c")
    project_dir = "/tmp/ghidra_project"
    # Clean project dir to avoid conflicts from previous runs
    shutil.rmtree(project_dir, ignore_errors=True)
    os.makedirs(project_dir, exist_ok=True)

    cmd = [
        os.path.join(GHIDRA_DIR, "support", "analyzeHeadless"),
        project_dir, "decompile_project",
        "-import", input_path,
        "-scriptPath", os.path.join(GHIDRA_DIR, "ghidra_scripts"),
        "-postScript", "ExportDecompiled.java", tmp_out,
        "-deleteProject",
    ]

    print(f"[Ghidra] Decompiling {input_path} ...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=GHIDRA_TIMEOUT)
        if result.returncode != 0:
            print(f"[Ghidra] Warning: exit code {result.returncode}", file=sys.stderr)
            if result.stderr:
                print(result.stderr[:2000], file=sys.stderr)
    except subprocess.TimeoutExpired:
        print(f"[Ghidra] Timeout after {GHIDRA_TIMEOUT}s for {input_path}", file=sys.stderr)

    if os.path.exists(tmp_out) and os.path.getsize(tmp_out) > 0:
        shutil.move(tmp_out, out_path)
        return out_path

    # Fallback to RetDec
    return decompile_retdec(input_path, output_dir, file_type)


def decompile_ar_archive(archive_path, output_dir):
    """Extract ar archive, classify members, decompile real code, list import stubs."""
    out_path = output_path_for(archive_path, output_dir, "ar_archive")
    os.makedirs(output_dir, exist_ok=True)

    try:
        members, tmp_dir = extract_ar_archive(archive_path)
    except Exception as e:
        print(f"[ar] Failed to extract {archive_path}: {e}", file=sys.stderr)
        return None

    if not members:
        return None

    decompiled_output = []   # (member_name, content_string)
    import_symbols = []      # (dll_name, member_name, [symbols])
    stub_members = []        # import stub members with disassembly

    for member_path in members:
        member_type = detect_type(member_path)
        member_name = os.path.basename(member_path)
        print(f"[ar] Member {member_name} → {member_type}")

        # COFF short import object (no sections, just header + strings)
        if member_type == "unknown" and is_import_stub(member_path):
            dll_name, syms = parse_coff_import_symbols(member_path)
            if syms:
                import_symbols.append((dll_name, member_name, syms))
            else:
                # Try nm to get symbol name
                nm_result = subprocess.run(
                    ["nm", member_path], capture_output=True, text=True, timeout=10
                )
                if nm_result.returncode == 0 and nm_result.stdout.strip():
                    syms = [l.split()[-1] for l in nm_result.stdout.splitlines() if l.strip()]
                    import_symbols.append(("unknown", member_name, syms))
            continue

        # Check if member is an import stub (has .text with only jmp *[IAT])
        if is_import_stub(member_path):
            # Get symbol name from objdump
            disasm = objdump_disassemble(member_path)
            if disasm:
                stub_members.append((member_name, disasm))
            # Also try nm
            nm_result = subprocess.run(
                ["nm", "--defined-only", member_path],
                capture_output=True, text=True, timeout=10
            )
            if nm_result.returncode == 0:
                syms = [l.split()[-1] for l in nm_result.stdout.splitlines()
                        if l.strip() and not l.strip().startswith('.')]
                if syms:
                    import_symbols.append(("unknown", member_name, syms))
            continue

        # Real code: decompile with Ghidra
        if member_type in ("elf", "coff", "pe_native", "unknown"):
            tmp_out = os.path.join("/tmp", f"ghidra_out_{member_name}.c")
            project_dir = "/tmp/ghidra_project"
            shutil.rmtree(project_dir, ignore_errors=True)
            os.makedirs(project_dir, exist_ok=True)
            cmd = [
                os.path.join(GHIDRA_DIR, "support", "analyzeHeadless"),
                project_dir, "decompile_project",
                "-import", member_path,
                "-scriptPath", os.path.join(GHIDRA_DIR, "ghidra_scripts"),
                "-postScript", "ExportDecompiled.java", tmp_out,
                "-deleteProject",
            ]
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=GHIDRA_TIMEOUT)
            except subprocess.TimeoutExpired:
                print(f"[Ghidra] Timeout for {member_path}", file=sys.stderr)
            if os.path.exists(tmp_out) and os.path.getsize(tmp_out) > 0:
                with open(tmp_out, "r", errors="replace") as f:
                    decompiled_output.append((member_name, f.read()))

    # Write output
    has_content = False
    with open(out_path, "w") as out_f:
        # Real decompiled code
        for name, content in decompiled_output:
            has_content = True
            out_f.write(f"// ===== {name} (decompiled) =====\n")
            out_f.write(content)
            out_f.write("\n\n")

        # Import stub disassembly
        if stub_members:
            has_content = True
            out_f.write("// ===== Import Stubs (disassembly) =====\n\n")
            for name, disasm in stub_members:
                out_f.write(f"// --- {name} ---\n")
                out_f.write(disasm)
                out_f.write("\n")

        # Symbol list summary
        if import_symbols:
            has_content = True
            out_f.write("// ===== Import Symbol Table =====\n\n")
            for dll_name, member_name, syms in import_symbols:
                out_f.write(f"// DLL: {dll_name}  (from {member_name})\n")
                for sym in syms:
                    out_f.write(f"//   {sym}\n")
                out_f.write("\n")

    shutil.rmtree(tmp_dir, ignore_errors=True)
    return out_path if has_content else None


def decompile_retdec(input_path, output_dir, file_type):
    """Fallback decompiler using RetDec."""
    if not RETDEC or not os.path.exists(RETDEC):
        print("[RetDec] Not available, skipping fallback", file=sys.stderr)
        return None

    out_path = output_path_for(input_path, output_dir, file_type)
    cmd = [RETDEC, input_path, out_path]
    print(f"[RetDec] Decompiling {input_path} ...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=GHIDRA_TIMEOUT)
        if result.returncode != 0:
            print(f"[RetDec] Failed: exit code {result.returncode}", file=sys.stderr)
            return None
    except subprocess.TimeoutExpired:
        print(f"[RetDec] Timeout for {input_path}", file=sys.stderr)
        return None
    return out_path


def decompile_ilspy(input_path, output_dir, file_type):
    """Decompile .NET DLL/EXE using ILSpy CLI."""
    out_path = output_path_for(input_path, output_dir, file_type)
    os.makedirs(output_dir, exist_ok=True)

    tmp_dir = os.path.join("/tmp", "ilspy_out")
    os.makedirs(tmp_dir, exist_ok=True)

    cmd = [ILSPYCMD, input_path, tmp_dir]
    print(f"[ILSpy] Decompiling {input_path} ...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            print(f"[ILSpy] Failed: exit code {result.returncode}", file=sys.stderr)
            if result.stderr:
                print(result.stderr[:2000], file=sys.stderr)
            return None
    except subprocess.TimeoutExpired:
        print(f"[ILSpy] Timeout for {input_path}", file=sys.stderr)
        return None

    cs_files = list(Path(tmp_dir).glob("*.cs"))
    if cs_files:
        shutil.move(str(cs_files[0]), out_path)
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return out_path
    return None


def decompile_cfr(input_path, output_dir, file_type):
    """Decompile JAR or .class using CFR. Concatenate all .java into one output."""
    out_path = output_path_for(input_path, output_dir, file_type)
    os.makedirs(output_dir, exist_ok=True)

    tmp_dir = os.path.join("/tmp", "cfr_out")
    os.makedirs(tmp_dir, exist_ok=True)

    cmd = ["java", "-jar", CFR_JAR, input_path, "--outputdir", tmp_dir]
    print(f"[CFR] Decompiling {input_path} ...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            print(f"[CFR] Failed: exit code {result.returncode}", file=sys.stderr)
            if result.stderr:
                print(result.stderr[:2000], file=sys.stderr)
            return None
    except subprocess.TimeoutExpired:
        print(f"[CFR] Timeout for {input_path}", file=sys.stderr)
        return None

    java_files = sorted(Path(tmp_dir).rglob("*.java"))
    if java_files:
        with open(out_path, "w") as out_f:
            for jf in java_files:
                rel = jf.relative_to(tmp_dir)
                out_f.write(f"// ===== {rel} =====\n")
                with open(jf, "r", errors="replace") as in_f:
                    out_f.write(in_f.read())
                out_f.write("\n\n")
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return out_path
    return None


# ── Metadata ─────────────────────────────────────────────────────────

def write_metadata(input_path, output_dir, file_type, decompiler, output_file):
    basename = Path(input_path).name
    meta_path = os.path.join(output_dir, basename + ".json")
    meta = {
        "source": str(input_path),
        "type": file_type,
        "decompiler": decompiler,
        "output_file": str(output_file),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    return meta_path


# ── Single file processing ──────────────────────────────────────────

DECOMPILER_MAP = {
    "elf": ("Ghidra", decompile_ghidra),
    "pe_native": ("Ghidra", decompile_ghidra),
    "coff": ("Ghidra", decompile_ghidra),
    "ar_archive": ("Ghidra", decompile_ghidra),
    "dotnet": ("ILSpy", decompile_ilspy),
    "jar": ("CFR", decompile_cfr),
    "class": ("CFR", decompile_cfr),
}


def process_file(input_path, output_dir):
    file_type = detect_type(input_path)
    print(f"[Detect] {input_path} → {file_type}")

    if file_type not in DECOMPILER_MAP:
        print(f"[Skip] Unsupported type: {file_type}", file=sys.stderr)
        return False

    decompiler_name, decompile_fn = DECOMPILER_MAP[file_type]
    result_path = decompile_fn(input_path, output_dir, file_type)

    if result_path and os.path.exists(result_path):
        write_metadata(input_path, output_dir, file_type, decompiler_name, result_path)
        print(f"[OK] {input_path} → {result_path}")
        return True
    else:
        print(f"[FAIL] {input_path} decompilation produced no output", file=sys.stderr)
        return False


# ── Batch / recursive ───────────────────────────────────────────────

SUPPORTED_EXTENSIONS = {
    ".elf", ".exe", ".dll", ".so", ".o", ".obj",
    ".a", ".lib",
    ".jar", ".class", ".apk",
}


def should_process(path):
    ext = Path(path).suffix.lower()
    if ext in SUPPORTED_EXTENSIONS:
        return True
    if ext == "":
        try:
            magic = read_magic(path, 4)
            if magic[:4] == b"\x7fELF" or magic[:2] == b"MZ":
                return True
        except Exception:
            pass
    return False


def process_recursive(input_dir, output_dir):
    success = 0
    failed = 0
    for root, dirs, files in os.walk(input_dir):
        if output_dir and os.path.normpath(root).startswith(os.path.normpath(output_dir)):
            continue
        for fname in files:
            fpath = os.path.join(root, fname)
            if should_process(fpath):
                if process_file(fpath, output_dir):
                    success += 1
                else:
                    failed += 1
    print(f"\n[Summary] {success} succeeded, {failed} failed")
    return success, failed


# ── CLI ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Unified decompilation wrapper")
    parser.add_argument("input", help="Input file or directory")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR,
                        help="Output directory (default: /data/decompiled)")
    parser.add_argument("--recursive", action="store_true",
                        help="Recursively process directory")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    if args.recursive and os.path.isdir(args.input):
        process_recursive(args.input, args.output_dir)
    elif os.path.isfile(args.input):
        ok = process_file(args.input, args.output_dir)
        sys.exit(0 if ok else 1)
    else:
        print(f"Error: {args.input} is not a valid file or directory", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
