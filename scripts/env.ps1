# CloudPass development environment (Windows).
#
# Dot-source this file before running cargo:
#
#     . .\scripts\env.ps1
#     cargo test
#
# What it does
# ------------
#   * Finds the Visual Studio installation that has the C++ toolset.
#   * Imports the developer environment (vcvars64.bat), which is what puts link.exe on
#     PATH and sets LIB/INCLUDE for the Windows SDK.
#   * Puts cargo on PATH and pins the MSVC toolchain.
#
# Why vcvars rather than letting rustc find Visual Studio
# ------------------------------------------------------
# rustc's own MSVC detection does not recognise Visual Studio 18 (2026), so a plain
# `cargo build` fails with "linker `link.exe` not found" even though the toolset is
# installed. Running from a developer environment sidesteps that entirely: rustc finds
# link.exe on PATH and the SDK libraries through LIB.
#
# There used to be a GNU-toolchain fallback here, with a portable MinGW-w64 under
# .tools\mingw. It is no longer needed now that MSVC works, and Tauri requires MSVC on
# Windows, so this script deliberately has one path rather than two. The MinGW
# directory can be deleted.

$repoRoot = Split-Path -Parent $PSScriptRoot
$cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'

if (-not (Test-Path $cargoBin)) {
    throw "cargo not found at $cargoBin. Install Rust: https://rustup.rs"
}

# --- Visual Studio developer environment -----------------------------------

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) {
    throw "vswhere.exe not found. Install Visual Studio (or its Build Tools) with the C++ toolset."
}

$vsPath = & $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath 2>$null

if (-not $vsPath) {
    throw @'
No Visual Studio installation with the C++ toolset was found.

Install it with, for example:

  vs_installer.exe modify --installPath "<VS path>" `
    --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    --add Microsoft.VisualStudio.Component.Windows11SDK.26100 `
    --quiet --norestart

Note that the `Microsoft.VisualStudio.Workload.VCTools` id belongs to the separate
Build Tools SKU; on a Community install it is absent from the product graph, and the
installer exits successfully having done nothing.
'@
}

$vcvars = Join-Path $vsPath 'VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $vcvars)) {
    throw "vcvars64.bat not found under $vsPath"
}

# `set` after a successful `call` prints the environment vcvars just built. Importing it
# into this session is what makes a bare `cargo build` work without a separate
# Developer Command Prompt window.
$vcvarsOutput = cmd /c "call `"$vcvars`" >nul 2>&1 && set"
foreach ($line in $vcvarsOutput) {
    if ($line -match '^([^=]+)=(.*)$') {
        $name = $matches[1]
        $value = $matches[2]
        # Some of what vcvars exports is command prompt decoration, not something a
        # build needs.
        if ($name -in 'PROMPT', 'VSCMD_ARG_VCVARS_VER') { continue }
        try { Set-Item -Path "env:$name" -Value $value -ErrorAction Stop } catch { }
    }
}

# Prepend, so cargo wins over anything already on PATH.
$env:Path = "$cargoBin;$env:Path"

# Pin the toolchain, so a bare `cargo test` uses the same target this environment can
# actually link.
$env:RUSTUP_TOOLCHAIN = 'stable-x86_64-pc-windows-msvc'

if (-not (Get-Command link.exe -ErrorAction SilentlyContinue)) {
    throw "link.exe is still not on PATH after importing the developer environment."
}

Write-Host "CloudPass env ready" -ForegroundColor Green
Write-Host "  toolchain     : $env:RUSTUP_TOOLCHAIN"
Write-Host "  visual studio : $vsPath"
