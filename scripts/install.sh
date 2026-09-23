#!/bin/sh
# scripts/install.sh — install spore (and the spore-peer transport) from
# GitHub Releases, with checksum verification, for Linux / macOS / *BSD /
# WSL / MSYS2-style environments. The Windows-native installer is
# scripts/install.ps1.
#
#   curl -fsSL https://raw.githubusercontent.com/liqdmetal/spore/main/scripts/install.sh | sh
#
# Options (environment):
#   SPORE_RELEASE=v0.9.0   pin a release (default: latest)
#   SPORE_BIN_DIR=~/.local/bin   install directory (added to PATH if missing)
#   SPORE_RELEASE_BASE=URL override the release download base for testing
#                          (e.g. a file:// URL of a fake release directory)
#   SPORE_NO_PEER=1        skip the spore-peer transport binary
#   SPORE_NO_PATH=1        don't touch shell rc files at all
#
# Exit codes: 0 installed · 1 download/verify failure · 2 unsupported platform
# · 3 usage/internal error. With `set -eu`, any failed step aborts — partial
# installs are cleaned up (the binary is downloaded to a temp dir and only
# moved into place after its checksum verifies).

set -eu

REPO="${SPORE_REPO:-liqdmetal/spore}"
RELEASE="${SPORE_RELEASE:-latest}"

# --- platform detection ----------------------------------------------------
# (Go naming: goos-goarch. GOOS/GOARCH override the detection, Go-style, for
# unusual systems, cross-checking a box, and testing this script.)
OS="${GOOS:-$(uname -s)}"
ARCH="${GOARCH:-$(uname -m)}"
case "$OS" in
	linux|Linux) GOOS=linux ;;
	darwin|Darwin) GOOS=darwin ;;
	MINGW*|MSYS*|CYGWIN*|Windows) echo "install.sh: this looks like Windows — use scripts/install.ps1 (PowerShell)" >&2; exit 2 ;;
	*) echo "install.sh: unsupported OS '$OS' (Windows: use install.ps1)" >&2; exit 2 ;;
esac
case "$ARCH" in
	x86_64|amd64) GOARCH=amd64 ;;
	aarch64|arm64) GOARCH=arm64 ;;
	*) echo "install.sh: unsupported architecture '$ARCH'" >&2; exit 2 ;;
esac

BIN_DIR="${SPORE_BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$BIN_DIR"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

base_url() {
	if [ -n "${SPORE_RELEASE_BASE:-}" ]; then
		printf '%s' "${SPORE_RELEASE_BASE%/}"
	elif [ "$RELEASE" = "latest" ]; then
		printf 'https://github.com/%s/releases/latest/download' "$REPO"
	else
		printf 'https://github.com/%s/releases/download/%s' "$REPO" "$RELEASE"
	fi
}

fetch() {
	# file:// support (local testing of this script); curl elsewhere.
	case "$1" in
		file://*) cp "$(_url_to_path "$1")" "$2" ;;
		*) curl -fsSL --retry 3 -o "$2" "$1" ;;
	esac
}

_url_to_path() {
	# file://host/path → path (localhost/empty host). Percent-decode %20 etc.
	p="${1#file://}"
	case "$p" in
		/*) ;;
		*) p="/$p" ;;
	esac
	# decode %XX without external deps
	printf '%b' "$(printf '%s' "$p" | sed 's/%/\\x/g')"
}

sum_file() {
	# sha256 with whatever the platform has (coreutils, busybox, macOS).
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
	elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
	else echo "install.sh: no sha256 tool found (need sha256sum or shasum)" >&2; exit 3; fi
}

install_one() {
	name="$1"
	required="${2:-required}"   # "required" | "optional"
	url="$(base_url)/$name"
	sums="$TMP/$name.sha256"
	echo "install.sh: downloading $name"
	if ! fetch "$url.sha256" "$sums"; then
		if [ "$required" = "optional" ]; then
			echo "install.sh: note: no spore-peer asset for this platform in this release; skipping (not an error)" >&2
			return 0
		fi
		echo "install.sh: failed to download $name.sha256" >&2
		return 1
	fi
	fetch "$url" "$TMP/$name"
	want="$(cut -d' ' -f1 "$sums")"
	got="$(sum_file "$TMP/$name")"
	# String equality on two fixed-width hex digests. A mismatch is always
	# fatal — checksum verification is never optional.
	if [ "$want" != "$got" ]; then
		echo "install.sh: CHECKSUM MISMATCH for $name" >&2
		echo "  want: $want" >&2
		echo "  got:  $got" >&2
		exit 1
	fi
	mv "$TMP/$name" "$BIN_DIR/$name"
	chmod +x "$BIN_DIR/$name"
	echo "install.sh: installed $BIN_DIR/$name (checksum ok)"
}

install_one "spore-$GOOS-$GOARCH"

if [ -z "${SPORE_NO_PEER:-}" ]; then
	# The transport is optional per-platform (some release matrices ship fewer
	# spore-peer targets than spore targets); a missing asset warns, a
	# corrupted one still hard-fails.
	install_one "spore-peer-$GOOS-$GOARCH" optional
fi

# --- PATH ------------------------------------------------------------------
case ":$PATH:" in
	*":$BIN_DIR:"*) ;;
	*)
		if [ -z "${SPORE_NO_PATH:-}" ]; then
			for rc in "$HOME/.profile" "$HOME/.zshrc" "$HOME/.bashrc"; do
				[ -f "$rc" ] || continue
				case "$(cat "$rc")" in
					*".local/bin"*) ;;
					*) printf '\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$rc"
					   echo "install.sh: added $BIN_DIR to PATH via $rc (restart your shell)" ;;
				esac
			done
		else
			echo "install.sh: note: $BIN_DIR is not on PATH (SPORE_NO_PATH set)"
		fi
		;;
esac

echo ""
echo "Spore installed. Next steps:"
echo "  spore demo        # full send → receive → burn lifecycle, no wallet"
echo "  spore init        # create your identity"
echo "  docs: https://github.com/$REPO/blob/main/docs/ONBOARDING.md"
