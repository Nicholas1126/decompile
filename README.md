# Docker Reverse - Unified Decompilation Toolchain

A Docker-based unified decompilation toolchain that converts binary files (ELF, PE/DLL, JAR, .class, .NET) into readable source code. All decompilers run inside a single Docker container — the host machine only needs Docker installed.

## Architecture

```
Host Machine (only Docker required)
  │
  └─ docker run --rm -v <data_dir>:/data decompiler <args>
         │
         └─ Container: decompile.py
              │
              ├─ File type detection (magic bytes)
              │
              ├─ ELF / native PE  ──>  Ghidra headless  ──> .cpp
              │                       (fallback: RetDec)
              │
              ├─ .NET DLL/EXE     ──>  ILSpy CLI         ──> .cs
              │
              └─ JAR / .class     ──>  CFR               ──> .java
```

## Supported File Types

| Input Type | Detection | Decompiler | Output Extension |
|------------|-----------|------------|------------------|
| ELF binary | `\x7fELF` magic | Ghidra 11.2.1 | `.cpp` |
| Native PE (DLL/EXE) | `MZ` header, no CLR | Ghidra 11.2.1 | `.cpp` |
| .NET assembly | `MZ` header + CLR | ILSpy (ICSharpCode.Decompiler 9.1) | `.cs` |
| Java JAR | `PK\x03\x04` + MANIFEST.MF | CFR 0.152 | `.java` |
| Java .class | `\xCA\xFE\xBA\xBE` | CFR 0.152 | `.java` |

## Prerequisites

- **Docker Desktop** installed and running
- ~5 GB disk space for the Docker image

## Quick Start

### 1. Build the Image

```bash
docker build -t decompiler:latest .
```

First build takes 15-20 minutes (downloads Ghidra ~400MB, .NET SDK, JDK 21, etc.). Subsequent builds use cached layers.

Alternatively, use the one-click setup script (Windows PowerShell):

```powershell
.\setup.ps1
# Or with a test data directory:
.\setup.ps1 -TestDataDir C:\cyber-security
```

### 2. Decompile a Single File

```bash
# Linux/macOS
docker run --rm -v /path/to/data:/data decompiler:latest /data/target.jar

# Windows (Git Bash - use MSYS_NO_PATHCONV=1 to prevent path conversion)
MSYS_NO_PATHCONV=1 docker run --rm -v "C:\path\to\data:/data" decompiler:latest /data/target.jar

# Windows (PowerShell)
docker run --rm -v "C:\path\to\data:/data" decompiler:latest /data/target.jar
```

### 3. Batch Decompile (Recursive)

```bash
docker run --rm -v /path/to/data:/data decompiler:latest /data --recursive --output-dir /data/decompiled
```

### 4. Custom Output Directory

```bash
docker run --rm -v /path/to/data:/data -v /path/to/output:/output decompiler:latest /data --recursive --output-dir /output
```

## Output Naming Rules

Output files are named by the original filename + decompiled extension:

| Input | Output | Description |
|-------|--------|-------------|
| `test` (ELF) | `test.cpp` | Native binary → C pseudocode |
| `test.dll` (native PE) | `test.dll.cpp` | Native DLL → C pseudocode |
| `test.dll` (.NET) | `test.dll.cs` | .NET assembly → C# source |
| `test.jar` | `test.jar.java` | Java JAR → Java source |

If a file with the same name already exists in the output directory, a date suffix is automatically added:

| Input | Existing? | Output |
|-------|-----------|--------|
| `test.jar` | No | `test.jar.java` |
| `test.jar` | Yes | `test.jar.20260429.java` |

A `.json` metadata file is also generated alongside each decompiled output.

## Usage Examples

### Decompile a JAR file

```bash
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "C:\cyber-security:/data" \
  -v "C:\cyber-security\decompiled:/output" \
  decompiler:latest /data/test.jar --output-dir /output
```

Output: `test.jar.java`

### Decompile a native DLL

```bash
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "C:\cyber-security:/data" \
  -v "C:\cyber-security\decompiled:/output" \
  decompiler:latest /data/test.dll --output-dir /output
```

Output: `test.dll.cpp`

### Decompile an ELF binary

```bash
docker run --rm -v /data/cyber-security:/data decompiler:latest /data/uaf --output-dir /data/decompiled
```

Output: `uaf.cpp`

## Project Structure

```
.
├── Dockerfile                          # Docker image definition
├── decompile.py                        # Container entry point: type detection & routing
├── ghidra_scripts/
│   └── ExportDecompiled.java           # Ghidra headless export script
├── ilspy-cli/
│   ├── Program.cs                      # ILSpy CLI wrapper (C#)
│   └── ilspy-cli.csproj               # Project file (ICSharpCode.Decompiler 9.1)
├── setup.ps1                           # Windows one-click setup script
├── .gitignore
└── README.md
```

## Docker Image Contents

| Component | Version | Purpose |
|-----------|---------|---------|
| Ubuntu | 22.04 | Base image |
| OpenJDK | 21 | Ghidra + CFR runtime |
| .NET SDK | 8.0 | Build ilspy-cli |
| Ghidra | 11.2.1 | ELF / native PE decompilation |
| CFR | 0.152 | JAR / .class decompilation |
| ILSpy (ilspy-cli) | 9.1 | .NET DLL/EXE decompilation |
| RetDec | optional | Fallback for native binaries |
| Python | 3.10 | Wrapper script runtime |

Image size: ~4.9 GB (compressed ~1.4 GB)

## Docker Proxy Configuration (China)

If Docker Hub is inaccessible, configure mirror and proxy:

1. Edit `~/.docker/daemon.json` — add registry mirrors:
```json
{
  "registry-mirrors": [
    "https://mirror.ccs.tencentyun.com",
    "https://docker.m.daocloud.io"
  ]
}
```

2. Edit Docker Desktop settings (`%APPDATA%/Docker/settings-store.json`) — add proxy:
```json
{
  "HttpProxy": "http://host.docker.internal:7897",
  "HttpsProxy": "http://host.docker.internal:7897",
  "NoProxy": "localhost,127.0.0.1,host.docker.internal"
}
```

3. Restart Docker Desktop.

## Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| `failed to authorize: failed to fetch oauth token` | Docker Hub unreachable | Configure proxy/mirrors (see above) |
| `Unable to prompt user for JDK path` | Ghidra can't find JDK in non-TTY | Already patched in Dockerfile (launch.sh uses JAVA_HOME) |
| `UnsupportedClassVersionError: class file version 65.0` | Ghidra 11.2+ needs JDK 21 | Dockerfile uses openjdk-21-jdk-headless |
| `libharfbuzz.so.0: cannot open shared object` | Missing font lib for Ghidra | Dockerfile installs libharfbuzz0b, libfreetype6, fontconfig |
| `Script not found: ExportDecompiled.java` | Ghidra can't find script path | decompile.py passes `-scriptPath` to analyzeHeadless |
| `ilspycmd failed to install` | NuGet package format incompatible | Uses custom ilspy-cli built from ICSharpCode.Decompiler NuGet |
| Path conversion errors on Windows | Git Bash converts `/data` paths | Use `MSYS_NO_PATHCONV=1` prefix |

## License

This project is provided for authorized security testing and educational purposes only.
