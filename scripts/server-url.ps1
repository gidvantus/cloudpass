# Reads the address a build is supposed to point at, and checks that a finished artifact
# actually carries it.
#
# Dot-source this; both build scripts use it.
#
# The check is the point of the file. The address is baked in at compile time by
# `desktop/build.rs`, and a build that quietly kept the previous one — a stale `target/`, a
# profile that never reached cargo — produces an installer that looks for a server on the
# machine it lands on. Nobody notices that until a user does, and by then the artifact is
# published and hashed.

function Get-ServerUrl {
    <#
    .SYNOPSIS
    The `url` under one profile in `desktop/server-url.toml`.
    #>
    param(
        [Parameter(Mandatory)][string]$ServerProfile
    )

    $config = Join-Path (Split-Path -Parent $PSScriptRoot) 'desktop/server-url.toml'
    $lines = Get-Content $config

    $start = ($lines | Select-String -Pattern "^\[$([regex]::Escape($ServerProfile))\]$" |
        Select-Object -First 1).LineNumber
    if (-not $start) { throw "$config has no [$ServerProfile] section" }

    for ($i = $start; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*url\s*=\s*"([^"]+)"') { return $Matches[1] }
    }
    throw "$config has no url under [$ServerProfile]"
}

function Assert-ArtifactCarriesUrl {
    <#
    .SYNOPSIS
    Fails unless the built artifact contains the address it was asked to bake in.

    .DESCRIPTION
    Latin-1 is used deliberately: it maps every byte to exactly one character, so searching a
    binary for the UTF-8 bytes of a URL becomes an ordinary string search. For an APK the
    search goes into the shared library the package carries, which is where the Rust half of
    the application — and therefore the address — lives.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Url
    )

    # Asked for by code page rather than through `[Text.Encoding]::Latin1`, which exists only
    # from .NET 5 on. These scripts run under whichever PowerShell the machine has, and Windows
    # ships 5.1 on .NET Framework.
    $latin1 = [System.Text.Encoding]::GetEncoding(28591)

    if ([System.IO.Path]::GetExtension($Path) -eq '.apk') {
        # Not available on its own under Windows PowerShell 5.1, where this type lives in an
        # assembly that has to be loaded first. Harmless where it is already present.
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

        $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
        try {
            foreach ($entry in $archive.Entries) {
                if ($entry.FullName -notlike 'lib/*/*.so') { continue }
                $stream = $entry.Open()
                try {
                    $buffer = New-Object System.IO.MemoryStream
                    $stream.CopyTo($buffer)
                    if ($latin1.GetString($buffer.ToArray()).Contains($Url)) { return }
                } finally {
                    $stream.Dispose()
                }
            }
        } finally {
            $archive.Dispose()
        }
    } elseif ($latin1.GetString([System.IO.File]::ReadAllBytes($Path)).Contains($Url)) {
        return
    }

    throw @"
$([System.IO.Path]::GetFileName($Path)) does not carry the address it was built for:
  expected: $Url

The build did not bake in the address it was asked for, so this artifact would look for a
server somewhere else. The usual cause is a `target/` directory that already held a build of
the other profile. `cargo clean -p cloudpass-desktop` and build again.
"@
}
