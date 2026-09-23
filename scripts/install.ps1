# scripts/install.ps1 — install spore (and the spore-peer transport) from
# GitHub Releases, with SHA-256 verification, for Windows 10+ / PowerShell 5.1+.
#
#  irm https://raw.githubusercontent.com/liqdmetal/spore/main/scripts/install.ps1 | iex
#
# Options (environment or param, for the scripted file use):
#   $env:SPORE_RELEASE     pin a release tag (default: latest)
#   $env:SPORE_BIN_DIR     install directory (default: ~\bin)
#   $env:SPORE_RELEASE_BASE  override the release download base for testing
#   $env:SPORE_NO_PEER=1   skip the spore-peer transport binary
#
# Binaries are downloaded to a temp directory and only moved into place after
# their checksum verifies — a failed download leaves any previous install
# untouched.

param(
	[string]$Release = "$env:SPORE_RELEASE",
	[string]$BinDir = "$env:SPORE_BIN_DIR",
	[string]$BaseUrl = "$env:SPORE_RELEASE_BASE"
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repo = 'liqdmetal/spore'
if (-not $Release) { $Release = 'latest' }
if (-not $BinDir) { $BinDir = Join-Path $HOME 'bin' }

# Force amd64 when running under 32-bit PowerShell on 64-bit Windows (the
# PROCESSOR_ARCHITECTURE of a Wow64 process lies about the machine).
$arch = $env:PROCESSOR_ARCHITEW6432
if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
switch -Regex ($arch) {
	'^(AMD64|x86_64)$' { $goarch = 'amd64' }
	'^(ARM64|aarch64)$' { $goarch = 'arm64' }
	default {
		Write-Error "install.ps1: unsupported architecture '$arch'"
		exit 2
	}
}

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$tmp = New-Item -ItemType Directory -Force -Path (Join-Path ([IO.Path]::GetTempPath()) ("spore-install-" + [IO.Path]::GetRandomFileName()))

function Get-ReleaseUrl([string]$name) {
	if ($BaseUrl) {
		return "$($BaseUrl.TrimEnd('/'))/$name"
	}
	if ($Release -eq 'latest') {
		return "https://github.com/$Repo/releases/latest/download/$name"
	}
	return "https://github.com/$Repo/releases/download/$Release/$name"
}

function Install-One([string]$name, [string]$required = 'required') {
	$url = Get-ReleaseUrl $name
	Write-Host "install.ps1: downloading $name"
	$sumsPath = Join-Path $tmp "$name.sha256"
	try {
		Invoke-WebRequest -UseBasicParsing -Uri "$url.sha256" -OutFile $sumsPath
	} catch {
		if ($required -eq 'optional') {
			Write-Host "install.ps1: note: no $name asset in this release; skipping (not an error)"
			return
		}
		throw
	}
	Invoke-WebRequest -UseBasicParsing -Uri "$url" -OutFile (Join-Path $tmp $name)
	$want = ((Get-Content $sumsPath -TotalCount 1) -split '\s+')[0].ToLower()
	$got = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $name)).Hash.ToLower()
	if ($want -ne $got) {
		Write-Error "install.ps1: CHECKSUM MISMATCH for $name`n  want: $want`n  got:  $got"
		exit 1
	}
	Move-Item -Force (Join-Path $tmp $name) (Join-Path $BinDir $name)
	Write-Host "install.ps1: installed $(Join-Path $BinDir $name) (checksum ok)"
}

Install-One "spore-windows-$goarch.exe"
if ($env:SPORE_NO_PEER -ne '1') {
	# The transport is optional per-platform; a missing asset warns, a
	# corrupted one still hard-fails.
	Install-One "spore-peer-windows-$goarch.exe" 'optional'
}

Remove-Item -Recurse -Force $tmp

# --- PATH (user scope, no admin needed; SPORE_NO_PATH=1 skips) -------------
$binDirNorm = (Resolve-Path $BinDir).Path
if ($env:SPORE_NO_PATH -eq '1') {
	Write-Host "install.ps1: note: $binDirNorm was not added to PATH (SPORE_NO_PATH set)"
} else {
	$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
	if (($userPath -split ';') -notcontains $binDirNorm) {
		[Environment]::SetEnvironmentVariable('Path', "$userPath;$binDirNorm", 'User')
		Write-Host "install.ps1: added $binDirNorm to your user PATH (restart your terminal)"
	}
}

Write-Host ""
Write-Host "Spore installed. Next steps:"
Write-Host "  spore demo        # full send -> receive -> burn lifecycle, no wallet"
Write-Host "  spore init        # create your identity"
Write-Host "  docs: https://github.com/$Repo/blob/main/docs/ONBOARDING.md"
