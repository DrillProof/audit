#!/bin/sh
#
# DrillProof CLI installer — the script served at https://get.drillproof.com
#
#   curl -fsSL https://get.drillproof.com | sh
#
# Deliberately POSIX sh, not bash: it has to run on Alpine CI images and minimal
# containers where bash is absent.
#
# What it does NOT do, on purpose:
#   - never sudo. It installs to a user-writable directory and tells you if that
#     is not on PATH. A curl|sh that silently escalates is how supply-chain
#     incidents start.
#   - never install an unverified binary. The checksum is fetched from the same
#     release and verified before anything is moved into place.
#
set -eu

REPO="DrillProof/audit"
BINARY="drillproof"
# Overridable: INSTALL_DIR=/usr/local/bin curl -fsSL … | sh
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${VERSION:-latest}"

err() {
	printf '\033[31merror:\033[0m %s\n' "$1" >&2
	exit 1
}
info() { printf '  %s\n' "$1"; }

need() { command -v "$1" >/dev/null 2>&1 || err "$1 is required but not installed."; }
need uname
need mktemp

# ── platform ────────────────────────────────────────────────────────────────
os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
Linux) os="Linux" ;;
Darwin) os="Darwin" ;;
*) err "unsupported OS: $os. Windows users: download the .zip from https://github.com/$REPO/releases" ;;
esac

case "$arch" in
x86_64 | amd64) arch="x86_64" ;;
arm64 | aarch64) arch="arm64" ;;
*) err "unsupported architecture: $arch" ;;
esac

# ── resolve the version ─────────────────────────────────────────────────────
if [ "$VERSION" = "latest" ]; then
	need curl
	# Follows GitHub's redirect from /releases/latest to the tagged URL and reads
	# the tag off the end. Avoids needing jq for one field.
	resolved="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
		"https://github.com/$REPO/releases/latest")"
	case "$resolved" in
	*/tag/*) VERSION="${resolved##*/tag/}" ;;
	*)
		# No release published yet: GitHub serves /releases instead of
		# redirecting to a tag, so there is nothing to parse. Say that,
		# rather than trying to download a URL built from an unparsed page.
		err "no published release found for $REPO yet. Build from source instead:
    go install github.com/drillproof/audit/cmd/drillproof@master" ;;
	esac
fi
info "installing $BINARY $VERSION ($os/$arch)"

# Must match `archives.name_template` in .goreleaser.yaml:
#   {{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}
# goreleaser's .Version is the tag without the leading "v", hence ${VERSION#v}.
# If that template changes, this line changes with it.
archive="drillproof-audit_${VERSION#v}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/$VERSION"

tmp="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '$tmp'" EXIT INT TERM

# ── download + verify ───────────────────────────────────────────────────────
need curl
curl -fsSL "$base/$archive" -o "$tmp/$archive" || err "download failed: $base/$archive"
curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt" || err "could not fetch checksums.txt"

if command -v sha256sum >/dev/null 2>&1; then
	(cd "$tmp" && grep " $archive\$" checksums.txt | sha256sum -c -) >/dev/null 2>&1 ||
		err "checksum mismatch — refusing to install. Report this."
elif command -v shasum >/dev/null 2>&1; then
	(cd "$tmp" && grep " $archive\$" checksums.txt | shasum -a 256 -c -) >/dev/null 2>&1 ||
		err "checksum mismatch — refusing to install. Report this."
else
	err "neither sha256sum nor shasum found; refusing to install unverified."
fi
info "checksum verified"

# ── install ─────────────────────────────────────────────────────────────────
tar -xzf "$tmp/$archive" -C "$tmp" || err "could not extract $archive"
[ -f "$tmp/$BINARY" ] || err "archive did not contain a '$BINARY' binary"

mkdir -p "$INSTALL_DIR"
mv "$tmp/$BINARY" "$INSTALL_DIR/$BINARY"
chmod +x "$INSTALL_DIR/$BINARY"

# macOS quarantines anything downloaded and not notarised; the first run would
# die with "cannot be opened because the developer cannot be verified".
if [ "$os" = "Darwin" ] && command -v xattr >/dev/null 2>&1; then
	xattr -d -r com.apple.quarantine "$INSTALL_DIR/$BINARY" 2>/dev/null || true
fi

info "installed to $INSTALL_DIR/$BINARY"

case ":$PATH:" in
*":$INSTALL_DIR:"*) ;;
*)
	printf '\n  %s is not on your PATH. Add it:\n\n    export PATH="%s:$PATH"\n\n' \
		"$INSTALL_DIR" "$INSTALL_DIR"
	;;
esac

printf '\n  Try it:\n    %s audit version\n    %s audit scan --region <your-region>\n\n' "$BINARY" "$BINARY"
