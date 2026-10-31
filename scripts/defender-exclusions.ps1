# defender-exclusions.ps1 — stop Defender's real-time scanner from taxing every
# Go build on this box.
#
# Why this exists: `go test -race` (the gates.sh -race gate) measured 58.5
# CPU-seconds of MsMpEng scanning during 86 s of gate time — ~0.7 of a core
# spent re-reading files the compiler had just written. The gate writes tens of
# thousands of object files per run into GOCACHE and %TEMP%\go-build*, none of
# which were excluded, so the scan cost was paid on every push.
#
# What gets excluded, and why each one:
#   GOCACHE          every compiled package archive; rewritten constantly
#   GOMODCACHE       read-only module sources; scanned on every build
#   GOROOT           toolchain sources + compiler binaries, invoked per package
#   GOTMPDIR         where `go test` links and runs test binaries; the default
#                    (%TEMP%\go-buildNNNN) is a fresh random dir per run, which
#                    cannot be excluded by path — so we pin it to one fixed dir
#   repo path        build artifacts and test scratch written inside the tree
#
# ExclusionPath does not support wildcards, which is the whole reason GOTMPDIR
# is pinned rather than excluding a pattern.
#
# Idempotent: re-running adds nothing twice and reports what it found. Must run
# elevated (Add-MpPreference -ExclusionPath needs administrator). Re-run after a
# Defender policy reset, a fresh clone on a new machine, or a GOCACHE move.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/defender-exclusions.ps1

param(
    [string]$RepoPath = (Split-Path -Parent $PSScriptRoot),
    [string]$GoTmpDir = "$env:LOCALAPPDATA\go-tmp",
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Prefer whichever `go` this shell already has; only fall back to the usual
# install locations when PATH has none, so this works on a box where Go lives
# somewhere else.
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    $candidates = @(
        "$env:ProgramFiles\Go\bin",
        "$env:LOCALAPPDATA\Programs\Go\bin",
        (Join-Path $env:USERPROFILE 'go-toolchain\go\bin'),
        (Join-Path $env:USERPROFILE 'scoop\apps\go\current\bin')
    )
    $env:Path = (@($candidates) + @($env:Path)) -join ';'
}
$go = Get-Command go -ErrorAction SilentlyContinue
if (-not $go) { throw "go not found on PATH; cannot resolve GOCACHE/GOMODCACHE" }

$gocache = (& go env GOCACHE).Trim()
$gomodcache = (& go env GOMODCACHE).Trim()
$goroot = (& go env GOROOT).Trim()
if (-not $gocache -or -not $gomodcache -or -not $goroot) {
    throw "go env returned an empty build path; refusing to guess"
}

# GOTMPDIR is pinned so the per-run random %TEMP%\go-buildNNNN directories
# collapse into a single excludable path.
$currentTmp = [Environment]::GetEnvironmentVariable('GOTMPDIR', 'User')
if ($currentTmp -ne $GoTmpDir) {
    if ($WhatIf) {
        Write-Host "would set GOTMPDIR (user) = $GoTmpDir  (was: $(if ($currentTmp) { $currentTmp } else { '<unset>' }))"
    } else {
        [Environment]::SetEnvironmentVariable('GOTMPDIR', $GoTmpDir, 'User')
        $env:GOTMPDIR = $GoTmpDir
        Write-Host "set GOTMPDIR (user) = $GoTmpDir  (was: $(if ($currentTmp) { $currentTmp } else { '<unset>'}))"
    }
}

$wanted = @($gocache, $gomodcache, $goroot, $GoTmpDir, $RepoPath)
$existing = @((Get-MpPreference).ExclusionPath | Where-Object { $_ })
$added = 0

foreach ($p in $wanted) {
    $dup = $existing | Where-Object { $_.TrimEnd('\') -ieq $p.TrimEnd('\') }
    if ($dup) {
        Write-Host "present: $p"
        continue
    }
    if ($WhatIf) {
        Write-Host "would add: $p"
        continue
    }
    if (-not (Test-Path -LiteralPath $p)) {
        New-Item -ItemType Directory -Force -Path $p | Out-Null
    }
    if (-not $elevated) {
        throw "not elevated: Add-MpPreference needs administrator. Re-run from an elevated shell."
    }
    Add-MpPreference -ExclusionPath $p -ErrorAction Stop
    Write-Host "added:   $p"
    $added++
}

if ($WhatIf) { return }

Write-Host ""
Write-Host "exclusion paths now in effect:"
(Get-MpPreference).ExclusionPath | ForEach-Object { "  $_" }
Write-Host ""
Write-Host "$added path(s) added this run."
Write-Host "note: GOTMPDIR takes effect for new processes; this shell needs it exported too."
