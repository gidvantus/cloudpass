# Builds the web portal: the wasm module, its JavaScript glue, and nothing else.
#
# Run from the repository root:  .\scripts\build-web.ps1  [-Debug]
#
# The output lands in apps/web/ui/pkg/, which is what the server serves. It is generated,
# not source: `cargo build` alone does not produce it, and a checkout without running this
# will serve a portal whose module is missing.
#
# `$ErrorActionPreference` stays at Continue on purpose. Cargo writes progress to stderr,
# and with the policy set to Stop PowerShell turns that into a terminating error that has
# nothing to do with whether the build worked. Success is decided by `$LASTEXITCODE`, which
# is what actually knows.

param(
    [switch]$Debug
)

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$profileName = if ($Debug) { 'debug' } else { 'release' }
$target = 'wasm32-unknown-unknown'

Write-Host "Building cloudpass-web ($profileName, $target)..."

if ($Debug) {
    cargo build --offline -p cloudpass-web --target $target
} else {
    cargo build --offline --release -p cloudpass-web --target $target
}
if ($LASTEXITCODE -ne 0) { throw "cargo build failed with $LASTEXITCODE" }

$wasm = Join-Path $root "target/$target/$profileName/cloudpass_web.wasm"
if (-not (Test-Path $wasm)) { throw "no wasm at $wasm" }

# `--target web` produces an ES module plus the wasm, with no bundler in the loop: the
# page imports the module directly and the browser fetches the wasm beside it.
# `--no-typescript` keeps the output to the two files the page actually uses.
Write-Host 'Running wasm-bindgen...'
wasm-bindgen --target web --out-dir "$root/apps/web/ui/pkg" --no-typescript $wasm
if ($LASTEXITCODE -ne 0) { throw "wasm-bindgen failed with $LASTEXITCODE" }

Get-ChildItem "$root/apps/web/ui/pkg" | Format-Table Name, Length
Write-Host 'Done.'
