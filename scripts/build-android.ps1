# Builds the Android application and puts the result where the server hands it out.
#
#   .\scripts\build-android.ps1
#   → web/web/ui/download/CloudPass_<version>_android.apk
#
# Why the artifact lands inside the web root: the server already serves that directory, and
# `downloads.rs` looks for a build next to the portal. One convention means there is nothing to
# configure and no list of file names to keep in step — whatever build script runs last is what
# the landing page offers, and the server hashes it at startup so the published SHA-256 cannot
# go stale.
#
# The file is deliberately named with its version between underscores. That name is what the
# server parses to publish a version, and therefore what a client can compare itself against;
# the name Gradle produces (`app-universal-release.apk`) carries none.
#
# The toolchain (JDK, SDK, NDK) is expected under `.tools/`, which is where
# `scripts/install-android-toolchain.ps1` puts it. Nothing here reaches outside the repository,
# so a build cannot depend on what happens to be installed on the machine.
#
# `$ErrorActionPreference` stays at Continue on purpose. The Tauri CLI and Gradle write progress
# to stderr, and with the policy set to Stop PowerShell turns that into a terminating error that
# has nothing to do with whether the build worked. Success is decided by `$LASTEXITCODE`.

param(
    [string]$OutputDirectory = 'web/web/ui/download'
)

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# `cargo` builds the Rust half of the application, so the MSVC environment is needed here for
# the same reason it is needed for the desktop build.
. (Join-Path $PSScriptRoot 'env.ps1')

# --- the Android toolchain --------------------------------------------------

$tools = Join-Path $root '.tools'
$javaHome = Join-Path $tools 'jdk21'
$sdkRoot = Join-Path $tools 'android-sdk'

$missing = @()
if (-not (Test-Path (Join-Path $javaHome 'bin\java.exe'))) { $missing += "JDK at $javaHome" }
if (-not (Test-Path (Join-Path $sdkRoot 'cmdline-tools\latest\bin\sdkmanager.bat'))) {
    $missing += "Android SDK at $sdkRoot"
}
if ($missing.Count -gt 0) {
    throw @"
The Android toolchain is not installed:
  $(($missing -join "`n  "))

Run `.\scripts\install-android-toolchain.ps1` once — it downloads the JDK, the SDK and the NDK
into `.tools/` (a few gigabytes) and accepts the SDK licences.
"@
}

$env:JAVA_HOME = $javaHome
$env:ANDROID_HOME = $sdkRoot
$env:ANDROID_SDK_ROOT = $sdkRoot

# The NDK is installed side by side and versioned, so the newest one is found rather than named:
# a path pinned here would mean editing this script every time the SDK is updated.
$ndk = Get-ChildItem (Join-Path $sdkRoot 'ndk') -Directory -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending | Select-Object -First 1
if (-not $ndk) {
    throw "no NDK under $sdkRoot\ndk. Install one: sdkmanager --sdk_root=`"$sdkRoot`" ndk;27.2.12479018"
}
$env:NDK_HOME = $ndk.FullName
$env:ANDROID_NDK_HOME = $ndk.FullName

Write-Host "JDK : $env:JAVA_HOME"
Write-Host "SDK : $env:ANDROID_HOME"
Write-Host "NDK : $env:NDK_HOME"

# --- the Tauri CLI ----------------------------------------------------------

Push-Location (Join-Path $root 'desktop')
try {
    # `npm install` is not merely a convenience here. Gradle's Rust plugin builds the shared
    # library by running `npm run -- tauri android android-studio-script`, so a package.json and
    # an installed CLI are load-bearing parts of the Android build rather than build conveniences.
    if (-not (Test-Path 'node_modules')) {
        Write-Host 'Installing the Tauri CLI (npm install)...'
        npm install
        if ($LASTEXITCODE -ne 0) { throw "npm install failed with $LASTEXITCODE" }
    }

    Write-Host 'Building the Android application (release APK)...'
    npx tauri android build
    $tauriExit = $LASTEXITCODE
} finally {
    Pop-Location
}
if ($tauriExit -ne 0) { throw "the Tauri Android build failed with $tauriExit" }

# --- collect the artifact ---------------------------------------------------

$apkRoot = Join-Path $root 'desktop/gen/android/app/build/outputs/apk'
$candidates = Get-ChildItem $apkRoot -Recurse -Filter '*.apk' -ErrorAction SilentlyContinue

# Signed and release: `unsigned` is what the bundler produces without a keystore, and an APK
# Android refuses to install is not something to publish under a download link.
$artifact = $candidates |
    Where-Object { $_.FullName -match 'release' -and $_.Name -notmatch 'unsigned' } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $artifact) {
    $unsigned = $candidates | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($unsigned) {
        throw @"
The build produced only an unsigned APK ($($unsigned.Name)).

That means the signing key was not found: expected desktop/gen/android/keystore.properties,
naming a keystore and its alias. An unsigned APK cannot be installed on a device, so it is not
published.
"@
    }
    throw "the build produced no APK under $apkRoot"
}

# The version comes from the application's own manifest of itself, so the published file name
# and the version the server reads out of it cannot disagree with what was built.
$version = (Get-Content (Join-Path $root 'desktop/tauri.conf.json') -Raw | ConvertFrom-Json).version
$name = "CloudPass_${version}_android.apk"

$destination = Join-Path $root $OutputDirectory
New-Item -ItemType Directory -Force $destination | Out-Null

# Old builds are removed rather than accumulated, exactly as the desktop script does: the server
# offers the newest by modification time, and a directory that grows by one package per release
# would keep growing inside the Docker image without anybody noticing.
Get-ChildItem $destination -Include '*.apk' -File -ErrorAction SilentlyContinue | Remove-Item -Force

$target = Join-Path $destination $name
Copy-Item $artifact.FullName $target -Force

$hash = (Get-FileHash -Algorithm SHA256 $target).Hash.ToLowerInvariant()
$size = (Get-Item $target).Length

Write-Host ''
Write-Host "Placed:  $OutputDirectory/$name"
Write-Host "Size:    $([math]::Round($size / 1MB, 2)) MiB ($size bytes)"
Write-Host "SHA-256: $hash"
Write-Host ''
Write-Host 'The server publishes exactly this hash from /api/v1/meta at startup.'
