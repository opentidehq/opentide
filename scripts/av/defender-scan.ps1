<#
.SYNOPSIS
  Scan release artifacts with Microsoft Defender on a Windows runner and fail on any detection (#1743).

.DESCRIPTION
  Updates the signatures (`MpCmdRun -SignatureUpdate`), then scans each file under the given path with a
  custom scan (`MpCmdRun -Scan -ScanType 3 -File <file> -DisableRemediation`: nothing is quarantined or
  deleted) and parses the result. Archives are scanned from their extracted tree (scripts/av/extract.py), so
  the engine sees each binary on its own. Nothing is uploaded: Defender runs locally against its own
  signatures (cloud-delivered protection is the runner image's setting, not this script's).

  A scan is only worth its "no threats" if Defender looks at the files. GitHub's Windows images exclude
  `C:\` and `D:\` (where the artifacts are) and may run with real-time protection off, which would make
  every file "clean" in seconds. So the script logs the preferences it found (exclusions, real-time,
  cloud-delivered protection, sample submission), removes the path exclusions, keeps sample submission at
  never-send, updates the signatures, and scans an EICAR canary (the standard antivirus test string,
  assembled at run time so this file is not one) that Defender must detect: when it does not, nothing the
  script says about the artifacts means anything and it exits 2.

  Exit status: 0 no detection, 1 a detection or an unreadable result, 2 the scan could not run, or its
  canary was not detected.
#>
param(
  [Parameter(Mandatory = $true)][string]$Path,
  [string]$Report = ""
)
$ErrorActionPreference = 'Stop'

$mp = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
if (-not (Test-Path $mp)) {
  # A newer platform keeps MpCmdRun under ProgramData.
  $mp = Get-ChildItem (Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform') -Filter MpCmdRun.exe -Recurse -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $mp) { Write-Error 'MpCmdRun.exe was not found: Microsoft Defender is not installed on this runner'; exit 2 }
if (-not (Test-Path $Path)) { Write-Error "no such path: $Path"; exit 2 }

Write-Host "MpCmdRun: $mp"

function Show-Preferences([string]$When) {
  $p = Get-MpPreference
  Write-Host "Defender preferences ($When):"
  [pscustomobject]@{
    ExclusionPath                 = ($p.ExclusionPath -join '; ')
    ExclusionProcess              = ($p.ExclusionProcess -join '; ')
    ExclusionExtension            = ($p.ExclusionExtension -join '; ')
    DisableRealtimeMonitoring     = $p.DisableRealtimeMonitoring
    DisableBehaviorMonitoring     = $p.DisableBehaviorMonitoring
    DisableIOAVProtection         = $p.DisableIOAVProtection
    DisableScriptScanning         = $p.DisableScriptScanning
    DisableArchiveScanning        = $p.DisableArchiveScanning
    MAPSReporting                 = $p.MAPSReporting
    SubmitSamplesConsent          = $p.SubmitSamplesConsent
    CloudBlockLevel               = $p.CloudBlockLevel
    PUAProtection                 = $p.PUAProtection
  } | Format-List | Out-Host
}
Show-Preferences 'as the image has them'
# Nothing is submitted: the samples are never sent, whatever the image set (cloud-delivered protection
# itself is left as it is, and logged above).
try { Set-MpPreference -SubmitSamplesConsent NeverSend } catch { Write-Host "could not set SubmitSamplesConsent: $_" }
# Defender must look at the files: no path, process or extension is excluded from a scan.
$exclusions = (Get-MpPreference).ExclusionPath
if ($exclusions) { try { Remove-MpPreference -ExclusionPath $exclusions } catch { Write-Host "could not remove the path exclusions: $_" } }
$exclusions = (Get-MpPreference).ExclusionExtension
if ($exclusions) { try { Remove-MpPreference -ExclusionExtension $exclusions } catch { Write-Host "could not remove the extension exclusions: $_" } }
$exclusions = (Get-MpPreference).ExclusionProcess
if ($exclusions) { try { Remove-MpPreference -ExclusionProcess $exclusions } catch { Write-Host "could not remove the process exclusions: $_" } }
Show-Preferences 'after the exclusions are removed'
if ((Get-MpPreference).ExclusionPath) { Write-Error 'a path exclusion remains: the files would not be scanned'; exit 2 }

try { Update-MpSignature } catch { Write-Host "Update-MpSignature: $_" }
& $mp -SignatureUpdate | Out-Host
# The engine and signature versions go to the log: a verdict is only meaningful with them.
Get-MpComputerStatus | Select-Object AMProductVersion, AMEngineVersion, AntivirusSignatureVersion, AntivirusSignatureLastUpdated | Format-List | Out-Host

# The canary: the EICAR test string, in a file of its own in a folder of its own, scanned as the
# artifacts are. Real-time protection may remove it at once: that is a detection too.
$canaryDir = Join-Path ([System.IO.Path]::GetTempPath()) ('opentide-av-canary-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $canaryDir | Out-Null
$canary = Join-Path $canaryDir 'canary.com'
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
try { Set-Content -Path $canary -Value $eicar -NoNewline -Encoding ascii } catch { Write-Host "the canary could not be written (removed at once by real-time protection): $_" }
Start-Sleep -Seconds 2
$canaryOut = & $mp -Scan -ScanType 3 -File $canaryDir -DisableRemediation 2>&1 | Out-String
$canaryGone = -not (Test-Path $canary)
$canarySeen = ($canaryOut -match 'found (\d+) threats?') -or $canaryGone
if (-not $canarySeen) {
  $canaryOut | Out-Host
  Write-Error 'Defender did not detect the EICAR canary: it is not scanning, and its "no threats" means nothing here'
  exit 2
}
Write-Host ('canary: detected ({0})' -f $(if ($canaryGone) { 'removed by real-time protection' } else { 'found by the scan' }))
Remove-Item -Recurse -Force $canaryDir -ErrorAction SilentlyContinue

$all = if ((Get-Item $Path).PSIsContainer) { Get-ChildItem $Path -File -Recurse } else { Get-Item $Path }
if (-not $all) { Write-Error "nothing to scan under $Path"; exit 2 }
# Each binary is scanned on its own, so a verdict names the file; the whole tree is scanned once more
# at the end (one MpCmdRun call per file of a wheel's several hundred would take hours).
$binary = '.exe', '.dll', '.pyd', '.node', '.wasm', '.so', '.dylib', '.sys', '.msi', '.ps1', '.sh'
$files = @($all | Where-Object { $binary -contains $_.Extension.ToLowerInvariant() })

$lines = @()
$detected = @()
$root = (Get-Item $Path).FullName.TrimEnd('\')
foreach ($file in $files) {
  $out = & $mp -Scan -ScanType 3 -File $file.FullName -DisableRemediation 2>&1 | Out-String
  $threats = @()
  # `Scanning <file> found no threats.` / `found N threats.` (the text is Defender's), and the
  # threat names as it prints them: `Threat                  : Trojan:Win32/...`.
  if ($out -match 'found no threats') {
    $verdict = 'clean'
  } elseif ($out -match 'found (\d+) threats?') {
    $verdict = "DETECTED ($($Matches[1]))"
    $detected += $file.FullName
    $threats = [regex]::Matches($out, '(?m)^\s*Threat\s*:\s*(.+)$') | ForEach-Object { $_.Groups[1].Value.Trim() }
  } else {
    $verdict = 'UNREADABLE'
    $detected += $file.FullName
    $threats = @($out.Trim())
  }
  $relative = $file.FullName.Substring([Math]::Min($root.Length, $file.FullName.Length)).TrimStart('\')
  $lines += ('{0,-14} {1}' -f $verdict, $relative)
  foreach ($threat in $threats) { $lines += "    $threat" }
}

# The whole tree, in one scan: anything the extension filter left out.
$out = & $mp -Scan -ScanType 3 -File (Get-Item $Path).FullName -DisableRemediation 2>&1 | Out-String
if ($out -match 'found no threats') {
  $lines += ('{0,-14} {1}' -f 'clean', "(the whole tree, $($all.Count) file(s))")
} else {
  $detected += $Path
  $lines += ('{0,-14} {1}' -f 'DETECTED', "(the whole tree, $($all.Count) file(s))")
  $lines += [regex]::Matches($out, '(?m)^\s*Threat\s*:\s*(.+)$') | ForEach-Object { "    $($_.Groups[1].Value.Trim())" }
  if (-not ($out -match 'found \d+ threats?')) { $lines += $out.Trim() }
}
$status = Get-MpComputerStatus
$lines += "Defender engine $($status.AMEngineVersion), signatures $($status.AntivirusSignatureVersion) ($($status.AntivirusSignatureLastUpdated)); canary detected; cloud-delivered protection (MAPSReporting) $((Get-MpPreference).MAPSReporting), sample submission $((Get-MpPreference).SubmitSamplesConsent)"
$summary = "Defender: $($files.Count) binary file(s) and the whole tree ($($all.Count) file(s)) scanned, $($detected.Count) detection(s) or unreadable result(s)"
$lines += $summary
$lines | Out-Host
if ($Report) { $lines | Set-Content -Path $Report }
if ($detected.Count -gt 0) { exit 1 }
