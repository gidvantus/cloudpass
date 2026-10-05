# Builds the desktop application and puts the result where the server hands it out.
#
#   .\scripts\build-desktop.ps1
#   → web/web/ui/download/CloudPass_<version>_x64-setup.exe
#
# Why the artifact lands inside the web root: the server already serves that directory, and
# `downloads.rs` looks for a build next to the portal. One convention means there is nothing to
# configure and no list of file names to keep in step — whatever build script runs last is what
# the landing page offers, and the server hashes it at startup so the published SHA-256 cannot
# go stale.
#
# Run from the repository root, as the usage above says. The Tauri CLI is the one step that
# does not run there: it reads `tauri.conf.json` from the current directory, and with the
# application now in `desktop/` the build is started from that directory instead.
#
# The bundler needs the network the first time: it downloads the Tauri CLI (through npx) and
# NSIS. After that both are cached.
#
# `$ErrorActionPreference` stays at Continue on purpose. Cargo and the Tauri CLI write progress
# to stderr, and with the policy set to Stop PowerShell turns that into a terminating error that
# has nothing to do with whether the build worked. Success is decided by `$LASTEXITCODE`.

param(
    [string]$OutputDirectory = 'web/web/ui/download'
)

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# A GUI binary has to link against MSVC, and rustc cannot find Visual Studio 18 on its own.
# Sourcing this here rather than demanding it from the caller is the difference between a script
# that works when run and one that works when remembered correctly.
. (Join-Path $PSScriptRoot 'env.ps1')

Write-Host 'Building the desktop application (release, NSIS bundle)...'
Push-Location (Join-Path $root 'desktop')
try {
    npx --yes '@tauri-apps/cli@2' build
    $tauriExit = $LASTEXITCODE
} finally {
    Pop-Location
}
if ($tauriExit -ne 0) { throw "the Tauri build failed with $tauriExit" }

# The installer is preferred: it registers an uninstaller and a shortcut, which is what a person
# expects from something they downloaded. The bare executable is the fallback for a build made
# without the bundler.
$bundleDirectory = Join-Path $root 'target/release/bundle/nsis'
$artifact = Get-ChildItem $bundleDirectory -Filter '*-setup.exe' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $artifact) {
    $portable = Join-Path $root 'target/release/cloudpass-desktop.exe'
    if (-not (Test-Path $portable)) { throw 'the build produced neither an installer nor an executable' }
    Write-Warning 'No installer was produced; falling back to the portable executable.'
    $artifact = Get-Item $portable
}

$destination = Join-Path $root $OutputDirectory
New-Item -ItemType Directory -Force $destination | Out-Null

# Old builds are removed rather than accumulated. The server offers the newest by modification
# time, but a directory that grows by one installer per release would keep growing inside the
# Docker image, and nobody would notice until it was gigabytes.
Get-ChildItem $destination -Include '*.exe', '*.msi' -File -ErrorAction SilentlyContinue |
    Remove-Item -Force

$target = Join-Path $destination $artifact.Name
Copy-Item $artifact.FullName $target -Force

$hash = (Get-FileHash -Algorithm SHA256 $target).Hash.ToLowerInvariant()
$size = (Get-Item $target).Length

Write-Host ''
Write-Host "Placed:  $OutputDirectory/$($artifact.Name)"
Write-Host "Size:    $([math]::Round($size / 1MB, 2)) MiB ($size bytes)"
Write-Host "SHA-256: $hash"
Write-Host ''
Write-Host 'The server publishes exactly this hash from /api/v1/meta at startup.'
