# Creates the Android release signing key, and the properties file that points Gradle at it.
#
#   .\scripts\new-android-keystore.ps1
#
# Two files, both deliberately outside version control:
#
#   .tools/keystore/cloudpass-release.jks     the key itself
#   desktop/gen/android/keystore.properties   where it is, and its passwords
#
# Losing the key means no future build can be installed over an existing one: Android accepts an
# update only when it is signed by the same key. Publishing it lets anybody sign an update for
# this application id. Back both files up somewhere that is not this checkout.
#
# The password is generated here and written only to those files — never printed. `keystore.properties`
# sits beside the key, so backing up `.tools/keystore/` and that one file keeps the pair together.
#
# Re-running is safe: an existing key is left alone and its password is reused, so this cannot
# silently invalidate builds that were already signed.

param(
    [string]$Alias = 'cloudpass',
    [string]$DistinguishedName = 'CN=CloudPass, OU=Development, O=CloudPass, C=RU',
    [int]$ValidityDays = 10000
)

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$keytool = Join-Path $root '.tools\jdk21\bin\keytool.exe'
if (-not (Test-Path $keytool)) {
    $keytool = 'keytool'
    if (-not (Get-Command $keytool -ErrorAction SilentlyContinue)) {
        throw 'No keytool: run .\scripts\install-android-toolchain.ps1, or install a JDK 17+.'
    }
}

$keyDir = Join-Path $root '.tools\keystore'
New-Item -ItemType Directory -Force $keyDir | Out-Null
$jks = Join-Path $keyDir 'cloudpass-release.jks'
$propertiesPath = Join-Path $root 'desktop\gen\android\keystore.properties'

function Read-ExistingPassword {
    if (-not (Test-Path $propertiesPath)) { return $null }
    $line = Get-Content $propertiesPath | Select-String '^password=' | Select-Object -First 1
    if (-not $line) { return $null }
    $value = $line.Line -replace '^password=', ''
    if ([string]::IsNullOrEmpty($value)) { return $null }
    return $value
}

function New-RandomPassword {
    # Letters and digits only, and no backslash: the value is written into a Java .properties
    # file, where backslash is an escape character, and a password nobody can retype is worse
    # than one that is merely long.
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
    return -join (1..28 | ForEach-Object { $alphabet[(Get-Random -Maximum $alphabet.Length)] })
}

$password = Read-ExistingPassword
if (Test-Path $jks) {
    if (-not $password) {
        throw @"
The keystore exists but its password could not be read from $propertiesPath.

Nothing is overwritten, because regenerating the key would break updates for anyone who already
installed the application. Restore keystore.properties from your backup, or delete the keystore
deliberately if you accept that this is a new signing identity.
"@
    }
    Write-Host "Keystore already present, reusing its password: $jks"
} else {
    $password = New-RandomPassword

    & $keytool -genkeypair -v `
        -keystore $jks -storetype PKCS12 -alias $Alias `
        -keyalg RSA -keysize 4096 -validity $ValidityDays `
        -storepass $password -keypass $password `
        -dname $DistinguishedName 2>&1 |
        Select-String -Pattern 'Generating|Storing' | ForEach-Object { $_.Line }

    if ($LASTEXITCODE -ne 0) { throw "keytool failed with $LASTEXITCODE" }
    Write-Host "Created: $jks"
}

# Forward slashes, not backslashes. `java.util.Properties.load` treats a backslash as an escape
# character, so a Windows path written literally arrives mangled — `D:\Development\...` loses
# its separators and Gradle reports a keystore named `D:DevelopmentVideCodingCloudPass...`. Java
# accepts forward slashes on Windows, so writing them removes the trap instead of documenting it.
$storeFile = $jks -replace '\\', '/'

$properties = @"
# Where the Android release signing key is, and how to open it. Written by
# scripts/new-android-keystore.ps1; ignored by git, because anyone holding this file can sign an
# update for this application id.
#
# The path uses forward slashes on purpose: backslashes are escape characters in a .properties
# file, and Java accepts forward slashes on Windows.
storeFile=$storeFile
keyAlias=$Alias
password=$password
"@

Set-Content -Path $propertiesPath -Value $properties -Encoding UTF8
Write-Host "Wrote:    $propertiesPath"
Write-Host ''
Write-Host 'Keep both files: losing the key means no future build installs over the current one.'
