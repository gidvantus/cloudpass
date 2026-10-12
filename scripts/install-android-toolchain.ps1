# Installs the Android toolchain under `.tools/`, so the APK build needs nothing from the
# machine it runs on.
#
#   .\scripts\install-android-toolchain.ps1
#
# What lands where:
#
#   .tools/jdk21/            OpenJDK 21 (Microsoft build). Tauri's Android build needs 17+;
#                            21 is the current LTS and what Gradle 9 and AGP 9 are tested
#                            against.
#   .tools/android-sdk/      command-line tools, platform-tools, the build-tools and platform
#                            the project compiles against, and the NDK.
#   .tools/downloads/        the archives, kept so a re-run costs nothing.
#
# Why `.tools/` and not the usual locations: `.tools/` is ignored by git and lives inside the
# checkout, so a build reads exactly the toolchain this script installed. A developer who
# already has Android Studio can point `build-android.ps1` elsewhere by exporting JAVA_HOME,
# ANDROID_HOME and NDK_HOME — but the default has to be something that works from a fresh
# clone, and "install it yourself first" is not.
#
# This downloads roughly 1.5 GB and unpacks to roughly 6 GB.

param(
    # The platform the project compiles against. Note the minor version: Google now publishes
    # API levels as `android-37.0`, `android-37.1`, and a bare `android-37` does not exist.
    [string]$Platform = 'android-37.0',
    [string]$BuildTools = '37.0.0',
    [string]$Ndk = '27.2.12479018',
    [string]$CmdlineToolsBuild = '13114758',
    [string]$JdkUrl = 'https://aka.ms/download-jdk/microsoft-jdk-21-windows-x64.zip'
)

$root = Split-Path -Parent $PSScriptRoot
$tools = Join-Path $root '.tools'
$downloads = Join-Path $tools 'downloads'
$javaHome = Join-Path $tools 'jdk21'
$sdkRoot = Join-Path $tools 'android-sdk'
New-Item -ItemType Directory -Force $downloads | Out-Null

function Get-Archive {
    param([string]$Url, [string]$Path)

    if (Test-Path $Path) {
        Write-Host "[cached] $Path"
        return
    }
    Write-Host "[download] $Url"
    # curl rather than Invoke-WebRequest: the latter holds a few hundred megabytes in memory
    # before writing anything, and the NDK is most of a gigabyte.
    curl.exe -L --fail --retry 3 -o $Path $Url
    if ($LASTEXITCODE -ne 0) { throw "download failed ($LASTEXITCODE): $Url" }
}

# --- JDK --------------------------------------------------------------------

if (Test-Path (Join-Path $javaHome 'bin\java.exe')) {
    Write-Host "[cached] JDK at $javaHome"
} else {
    $jdkZip = Join-Path $downloads 'jdk21.zip'
    Get-Archive -Url $JdkUrl -Path $jdkZip

    $staging = Join-Path $downloads 'jdk-staging'
    Remove-Item -Recurse -Force $staging -ErrorAction SilentlyContinue
    Expand-Archive -Path $jdkZip -DestinationPath $staging -Force

    # The archive holds a directory named after the exact build, which changes with every patch
    # release; the path this script promises does not. So it is renamed rather than referenced.
    $inner = Get-ChildItem $staging -Directory | Select-Object -First 1
    Remove-Item -Recurse -Force $javaHome -ErrorAction SilentlyContinue
    Move-Item $inner.FullName $javaHome
    Remove-Item -Recurse -Force $staging -ErrorAction SilentlyContinue
    Write-Host "[ok] JDK at $javaHome"
}
& (Join-Path $javaHome 'bin\java.exe') -version 2>&1 | Select-Object -First 1

# --- command-line tools -----------------------------------------------------

$latest = Join-Path $sdkRoot 'cmdline-tools\latest'
$sdkmanager = Join-Path $latest 'bin\sdkmanager.bat'

if (Test-Path $sdkmanager) {
    Write-Host "[cached] sdkmanager at $sdkmanager"
} else {
    $cmdZip = Join-Path $downloads 'cmdline-tools.zip'
    Get-Archive -Url "https://dl.google.com/android/repository/commandlinetools-win-${CmdlineToolsBuild}_latest.zip" -Path $cmdZip

    $staging = Join-Path $downloads 'cmdline-staging'
    Remove-Item -Recurse -Force $staging -ErrorAction SilentlyContinue
    Expand-Archive -Path $cmdZip -DestinationPath $staging -Force

    # sdkmanager insists on finding itself under `cmdline-tools/latest`; anything else and it
    # reports that the SDK root is corrupt rather than saying what it actually wanted.
    New-Item -ItemType Directory -Force (Split-Path $latest) | Out-Null
    Remove-Item -Recurse -Force $latest -ErrorAction SilentlyContinue
    Move-Item (Join-Path $staging 'cmdline-tools') $latest
    Remove-Item -Recurse -Force $staging -ErrorAction SilentlyContinue
    Write-Host "[ok] sdkmanager at $sdkmanager"
}

# --- SDK packages -----------------------------------------------------------

$env:JAVA_HOME = $javaHome
$env:ANDROID_HOME = $sdkRoot
$env:ANDROID_SDK_ROOT = $sdkRoot

Write-Host 'Accepting the SDK licences...'
# Every licence prompt is answered yes. The packages below are the ones the build needs, and a
# half-accepted SDK fails later with a message about a missing package rather than a licence.
$answers = (1..100 | ForEach-Object { 'y' }) -join "`n"
$answers | & $sdkmanager --sdk_root=$sdkRoot --licenses 2>&1 | Select-Object -Last 2

Write-Host "Installing platform-tools, $Platform, build-tools;$BuildTools and ndk;$Ndk..."
& $sdkmanager --sdk_root=$sdkRoot 'platform-tools' $Platform "build-tools;$BuildTools" "ndk;$Ndk" 2>&1 |
    Select-String -NotMatch -Pattern '^\s*\[|^\s*$' | Select-Object -Last 10
if ($LASTEXITCODE -ne 0) { throw "sdkmanager failed with $LASTEXITCODE" }

Write-Host ''
Write-Host 'Installed:'
Get-ChildItem $sdkRoot -Directory | Select-Object -ExpandProperty Name | ForEach-Object { "  $_" }
foreach ($part in 'platforms', 'build-tools', 'ndk') {
    $dir = Join-Path $sdkRoot $part
    if (Test-Path $dir) {
        Get-ChildItem $dir -Directory | ForEach-Object { "  $part/$($_.Name)" }
    }
}
Write-Host ''
Write-Host 'The APK build is now:  .\scripts\build-android.ps1'
