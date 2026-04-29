#!/usr/bin/env python3
"""Unified decompilation wrapper — runs inside Docker container.

Detects file type via magic bytes and routes to the appropriate decompiler:
  - ELF / native PE  → Ghidra headless (fallback: RetDec)
  - .NET DLL/EXE     → ILSpy CLI
  - JAR / .class     → CFR

Output naming by file type:
  - ELF / native PE  → <name>.cpp        (e.g. test → test.cpp)
  - .NET DLL/EXE     → <name>.cs         (e.g. test.dll → test.dll.cs)
  - JAR / .class     → <name>.java       (e.g. test.jar → test.jar.java)
  If file already exists, insert date: <name>.YYYYMMDD.<ext>
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import struct
from datetime import datetime
from pathlib import Path

GHIDRA_DIR = os.environ.get("GHIDRA_DIR", "/opt/ghidra")
CFR_JAR = "/opt/cfr.jar"
ILSPYCMD = shutil.which("ilspy-cli") or "/opt/ilspy-cli/ilspy-cli"
RETDEC = shutil.which("retdec-decompiler") or ""

DEFAULT_OUTPUT_DIR = "/data/decompiled"


# ── File type detection ──────────────────────────────────────────────

def read_magic(path, n=8):
    with open(path, "rb") as f:
        return f.read(n)


def detect_type(path):
    """Return one of: 'elf', 'pe_native', 'dotnet', 'jar', 'class', 'unknown'."""
    magic = read_magic(path, 8)

    if magic[:4] == b"\x7fELF":
        return "elf"

    if magic[:4] == b"\xca\xfe\xba\xbe":
        return "class"

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

# Map file type to decompiled output extension
TYPE_EXT_MAP = {
    "elf": ".cpp",
    "pe_native": ".cpp",
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


# ── Decompilers ──────────────────────────────────────────────────────

def decompile_ghidra(input_path, output_dir, file_type):
    """Decompile ELF or native PE using Ghidra headless."""
    out_path = output_path_for(input_path, output_dir, file_type)
    os.makedirs(output_dir, exist_ok=True)

    # Ghidra exports to a temp path first
    tmp_out = os.path.join("/tmp", "ghidra_out.c")
    project_dir = "/tmp/ghidra_project"
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
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        print(f"[Ghidra] Warning: exit code {result.returncode}", file=sys.stderr)
        if result.stderr:
            print(result.stderr[:2000], file=sys.stderr)

    if os.path.exists(tmp_out) and os.path.getsize(tmp_out) > 0:
        shutil.move(tmp_out, out_path)
        return out_path

    # Fallback to RetDec
    return decompile_retdec(input_path, output_dir, file_type)


def decompile_retdec(input_path, output_dir, file_type):
    """Fallback decompiler using RetDec."""
    if not RETDEC or not os.path.exists(RETDEC):
        print("[RetDec] Not available, skipping fallback", file=sys.stderr)
        return None

    out_path = output_path_for(input_path, output_dir, file_type)
    cmd = [RETDEC, input_path, out_path]
    print(f"[RetDec] Decompiling {input_path} ...")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        print(f"[RetDec] Failed: exit code {result.returncode}", file=sys.stderr)
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
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        print(f"[ILSpy] Failed: exit code {result.returncode}", file=sys.stderr)
        if result.stderr:
            print(result.stderr[:2000], file=sys.stderr)
        return None

    # ilspy-cli outputs a single .cs file
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
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        print(f"[CFR] Failed: exit code {result.returncode}", file=sys.stderr)
        if result.stderr:
            print(result.stderr[:2000], file=sys.stderr)
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
