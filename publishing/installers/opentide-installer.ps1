# Installs opentide's standalone binaries, `opentide.exe` (the command line) and
# `opentide-lsp.exe` (the language server), from one GitHub Release of
# opentidehq/opentide, on Windows (x64, Arm64). Each binary is checked against
# the release's SHA256SUMS before it is installed.
#
#   powershell -ExecutionPolicy Bypass -c "irm https://github.com/opentidehq/opentide/releases/download/vX.Y.Z/opentide-installer.ps1 | iex"
#
# The release workflow (.github/workflows/publish.yml) writes the release's tag
# into $ReleaseTag below; the copy in the repository names none, and needs
# OPENTIDE_TAG set. Settings, from the environment:
#
#   OPENTIDE_INSTALL_DIR  where the binaries go (default: %LOCALAPPDATA%\opentide\bin)
#   OPENTIDE_TAG          the release to install (default: this installer's)
#   OPENTIDE_DOWNLOAD_URL where the release's assets are (default: the GitHub
#                         Release of OPENTIDE_TAG); the workflow's smoke test
#                         points it at the assets it built (a directory)
$ErrorActionPreference = 'Stop'

$ReleaseTag = '__OPENTIDE_TAG__'
$tag = if ($env:OPENTIDE_TAG) { $env:OPENTIDE_TAG } else { $ReleaseTag }
if ($tag -notmatch '^v[0-9]') { throw 'opentide-installer: set OPENTIDE_TAG to a release tag (vX.Y.Z)' }
$base = if ($env:OPENTIDE_DOWNLOAD_URL) { $env:OPENTIDE_DOWNLOAD_URL } else { "https://github.com/opentidehq/opentide/releases/download/$tag" }
$dir = if ($env:OPENTIDE_INSTALL_DIR) { $env:OPENTIDE_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'opentide\bin' }

$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
switch ($arch.ToString()) {
  'X64' { $target = 'x86_64-pc-windows-msvc' }
  'Arm64' { $target = 'aarch64-pc-windows-msvc' }
  default { throw "opentide-installer: no build for $arch" }
}

function Get-Asset([string]$Name, [string]$OutFile) {
  if (Test-Path -LiteralPath $base -PathType Container) {
    Copy-Item -LiteralPath (Join-Path $base $Name) -Destination $OutFile
  } else {
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$Name" -OutFile $OutFile
  }
}

$scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("opentide-" + [System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $scratch | Out-Null
try {
  Get-Asset 'SHA256SUMS' (Join-Path $scratch 'SHA256SUMS')
  $sums = @{}
  foreach ($line in Get-Content (Join-Path $scratch 'SHA256SUMS')) {
    if ($line -match '^([0-9a-f]{64}) [ *](\S+)$') { $sums[$Matches[2]] = $Matches[1] }
  }
  # Every binary is downloaded and checked before any is installed.
  foreach ($binary in @('opentide', 'opentide-lsp')) {
    $asset = "$binary-$tag-$target.exe"
    $file = Join-Path $scratch $asset
    Get-Asset $asset $file
    if (-not $sums.ContainsKey($asset)) { throw "opentide-installer: SHA256SUMS lists no $asset" }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant()
    if ($actual -ne $sums[$asset]) { throw "opentide-installer: $asset does not match SHA256SUMS" }
  }
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  foreach ($binary in @('opentide', 'opentide-lsp')) {
    $asset = "$binary-$tag-$target.exe"
    Move-Item -Force -LiteralPath (Join-Path $scratch $asset) -Destination (Join-Path $dir "$binary.exe")
    Write-Output "installed $(Join-Path $dir "$binary.exe") ($tag, $target)"
  }
} finally {
  Remove-Item -Recurse -Force -LiteralPath $scratch
}
if (-not (($env:PATH -split ';') -contains $dir)) {
  Write-Output "add $dir to PATH to run opentide"
}
