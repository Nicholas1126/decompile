<#
.SYNOPSIS
    One-click setup script for the Docker decompiler toolchain.
.DESCRIPTION
    Checks Docker Desktop, builds the decompiler image, and verifies it works.
.EXAMPLE
    .\setup.ps1
    .\setup.ps1 -TestDataDir C:\cyber-security
#>

param(
    [string]$TestDataDir = "",
    [switch]$SkipVerify
)

$ErrorActionPreference = "Stop"
$ImageName = "decompiler"
$ImageTag = "latest"

# ── Step 1: Check Docker ────────────────────────────────────────────

Write-Host "`n[1/3] Checking Docker..." -ForegroundColor Cyan

try {
    $dockerVersion = docker --version 2>&1
    Write-Host "  Docker found: $dockerVersion" -ForegroundColor Green
}
catch {
    Write-Host "  Docker not found. Please install Docker Desktop first:" -ForegroundColor Red
    Write-Host "  https://www.docker.com/products/docker-desktop" -ForegroundColor Yellow
    exit 1
}

# Check Docker daemon is running
try {
    $null = docker info 2>&1
    Write-Host "  Docker daemon is running" -ForegroundColor Green
}
catch {
    Write-Host "  Docker daemon is not running. Please start Docker Desktop." -ForegroundColor Red
    exit 1
}

# ── Step 2: Build image ─────────────────────────────────────────────

Write-Host "`n[2/3] Building Docker image ${ImageName}:${ImageTag}..." -ForegroundColor Cyan
Write-Host "  This may take 10-20 minutes on first build (downloading Ghidra, .NET SDK, etc.)" -ForegroundColor Yellow

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
docker build -t "${ImageName}:${ImageTag}" $scriptDir

if ($LASTEXITCODE -ne 0) {
    Write-Host "  Docker build failed!" -ForegroundColor Red
    exit 1
}
Write-Host "  Image built successfully" -ForegroundColor Green

# ── Step 3: Verify ──────────────────────────────────────────────────

if (-not $SkipVerify) {
    Write-Host "`n[3/3] Verifying image..." -ForegroundColor Cyan

    if ($TestDataDir -and (Test-Path $TestDataDir)) {
        $testDir = $TestDataDir
    }
    else {
        # Create a minimal test directory
        $testDir = Join-Path $env:TEMP "decompiler-test"
        if (-not (Test-Path $testDir)) {
            New-Item -ItemType Directory -Path $testDir -Force | Out-Null
        }
        Write-Host "  No test data directory specified, using temp dir: $testDir" -ForegroundColor Yellow
    }

    $testDirWin = $testDir
    $testDirDocker = $testDirWin -replace '\\', '/' -replace '^([A-Z]):', '/$1'

    # Check for test files
    $testFiles = @("test.jar", "test.dll", "uaf")
    $found = $false
    foreach ($tf in $testFiles) {
        if (Test-Path (Join-Path $testDir $tf)) {
            Write-Host "  Testing with $tf..." -ForegroundColor Yellow
            docker run --rm -v "${testDirWin}:${testDirDocker}" "${ImageName}:${ImageTag}" "${testDirDocker}/${tf}"
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  $tf decompilation OK" -ForegroundColor Green
            }
            else {
                Write-Host "  $tf decompilation FAILED" -ForegroundColor Red
            }
            $found = $true
        }
    }

    if (-not $found) {
        Write-Host "  No test files found in $testDir. Skipping verification." -ForegroundColor Yellow
        Write-Host "  To test later: docker run --rm -v <dir>:/data ${ImageName}:${ImageTag} /data/<file>" -ForegroundColor Yellow
    }
}
else {
    Write-Host "`n[3/3] Verification skipped (-SkipVerify)" -ForegroundColor Yellow
}

# ── Setup alias ─────────────────────────────────────────────────────

Write-Host "`nSetup complete!" -ForegroundColor Green
Write-Host @"
Usage:
  # Single file
  docker run --rm -v C:\your\data:/data ${ImageName}:${ImageTag} /data/target.jar

  # Batch (recursive)
  docker run --rm -v C:\your\data:/data ${ImageName}:${ImageTag} /data --recursive --output-dir /data/decompiled

  # Custom output directory
  docker run --rm -v C:\your\data:/data -v C:\output:/output ${ImageName}:${ImageTag} /data --recursive --output-dir /output
"@ -ForegroundColor White
