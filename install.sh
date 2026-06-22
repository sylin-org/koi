#!/bin/sh
# Koi installer for Linux and macOS (POSIX sh).
#
#   curl -fsSL https://raw.githubusercontent.com/sylin-org/koi/main/install.sh | sh
#
# Downloads the latest (or a pinned) release archive for this OS/arch from
# GitHub Releases, verifies its SHA-256 checksum, and installs the `koi`
# binary onto your PATH. It never compiles anything and never needs root for
# the default per-user install location.
#
# Knobs (environment variables):
#   KOI_VERSION        pin a release tag, e.g. v0.4.2   (default: latest)
#   KOI_INSTALL_DIR    install location                 (default: /usr/local/bin
#                                                         as root, else ~/.local/bin)
#   KOI_NO_MODIFY_PATH any non-empty value: don't print PATH guidance
#
# Example, pinning a version to a custom dir:
#   curl -fsSL .../install.sh | KOI_INSTALL_DIR=$HOME/bin KOI_VERSION=v0.4.2 sh

set -eu

REPO="sylin-org/koi"
BIN_NAME="koi"

# ── Output helpers ─────────────────────────────────────────────────
say() { printf 'koi: %s\n' "$1"; }
err() { printf 'koi: error: %s\n' "$1" >&2; exit 1; }

has() { command -v "$1" >/dev/null 2>&1; }

# download <dest|-> <url>   ("-" writes to stdout)
# Refuses non-HTTPS URLs and forbids redirect-to-HTTP downgrades, so a tampered
# mirror cannot serve a plaintext archive + matching checksum.
download() {
    _dest="$1"
    _url="$2"
    case "$_url" in
        https://*) : ;;
        *) err "refusing to download over a non-HTTPS URL: $_url" ;;
    esac
    if has curl; then
        if [ "$_dest" = "-" ]; then
            curl -fsSL --proto '=https' --tlsv1.2 "$_url"
        else
            curl -fsSL --proto '=https' --tlsv1.2 -o "$_dest" "$_url"
        fi
    elif has wget; then
        # --https-only blocks a redirect down to http://; the URL is already https.
        if [ "$_dest" = "-" ]; then
            wget --https-only --secure-protocol=TLSv1_2 -qO- "$_url"
        else
            wget --https-only --secure-protocol=TLSv1_2 -qO "$_dest" "$_url"
        fi
    else
        err "need either curl or wget to download Koi"
    fi
}

# sha256 of a file, lowercased hex, on stdout
sha256_of() {
    if has sha256sum; then
        sha256sum "$1" | cut -d' ' -f1
    elif has shasum; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        err "need either sha256sum or shasum to verify the download"
    fi
}

# Reject a tag that could escape a path or inject into a URL: only "v" + a
# conservative charset (letters, digits, dot, dash, underscore), no "..".
validate_tag() {
    case "$1" in
        v[0-9]*) : ;;
        *) err "unexpected version tag '$1' (want vMAJOR.MINOR.PATCH)" ;;
    esac
    case "$1" in
        *[!A-Za-z0-9._-]* | *..*) err "version tag '$1' has invalid characters" ;;
    esac
}

# ── Detect OS / arch → release target triple ───────────────────────
detect_target() {
    _os="$(uname -s)"
    _arch="$(uname -m)"
    case "$_os" in
        Linux)  _os="unknown-linux-musl" ;;
        Darwin) _os="apple-darwin" ;;
        *)      err "unsupported OS '$_os' (only Linux and macOS have prebuilt binaries; build from source instead)" ;;
    esac
    case "$_arch" in
        x86_64 | amd64)   _arch="x86_64" ;;
        aarch64 | arm64)  _arch="aarch64" ;;
        *)                err "unsupported architecture '$_arch'" ;;
    esac
    printf '%s-%s' "$_arch" "$_os"
}

# ── Resolve the release tag (latest unless pinned) ─────────────────
resolve_version() {
    if [ -n "${KOI_VERSION:-}" ]; then
        printf '%s' "$KOI_VERSION"
        return
    fi
    # Parse "tag_name" out of the GitHub "latest release" JSON without jq.
    _tag="$(download - "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | head -1 \
        | sed -e 's/.*"tag_name"[[:space:]]*:[[:space:]]*"//' -e 's/".*//')"
    [ -n "$_tag" ] || err "could not determine the latest release tag (set KOI_VERSION to pin one)"
    printf '%s' "$_tag"
}

# ── Choose an install directory ────────────────────────────────────
resolve_bin_dir() {
    if [ -n "${KOI_INSTALL_DIR:-}" ]; then
        printf '%s' "$KOI_INSTALL_DIR"
    elif [ "$(id -u)" = "0" ]; then
        printf '/usr/local/bin'
    else
        printf '%s/.local/bin' "$HOME"
    fi
}

main() {
    target="$(detect_target)"
    version="$(resolve_version)"
    # Normalise to a v-prefixed tag; archives are named koi-vX.Y.Z-<target>.
    case "$version" in
        v*) : ;;
        *)  version="v$version" ;;
    esac
    validate_tag "$version"
    bin_dir="$(resolve_bin_dir)"

    archive="${BIN_NAME}-${version}-${target}.tar.gz"
    base_url="https://github.com/${REPO}/releases/download/${version}"

    say "installing ${BIN_NAME} ${version} (${target}) to ${bin_dir}"

    tmp="$(mktemp -d 2>/dev/null || mktemp -d /tmp/koi.XXXXXX)"
    [ -n "$tmp" ] && [ -d "$tmp" ] || err "could not create a temp directory"
    # shellcheck disable=SC2064
    trap "rm -rf \"$tmp\"" EXIT INT TERM QUIT

    say "downloading ${archive}"
    download "${tmp}/${archive}" "${base_url}/${archive}" \
        || err "download failed — does ${version} have a ${target} build? (https://github.com/${REPO}/releases)"
    download "${tmp}/${archive}.sha256" "${base_url}/${archive}.sha256" \
        || err "could not download the checksum for ${archive}"

    # tr -d '\r' tolerates a checksum file served with CRLF endings.
    expected="$(cut -d' ' -f1 < "${tmp}/${archive}.sha256" | tr -d '\r')"
    actual="$(sha256_of "${tmp}/${archive}")"
    [ -n "$expected" ] || err "checksum file was empty"
    if [ "$expected" != "$actual" ]; then
        err "checksum mismatch for ${archive} (expected ${expected}, got ${actual})"
    fi
    say "checksum verified"

    tar -xzf "${tmp}/${archive}" -C "$tmp" || err "could not extract ${archive}"
    extracted="${tmp}/${BIN_NAME}-${version}-${target}/${BIN_NAME}"
    [ -f "$extracted" ] || err "archive did not contain ${BIN_NAME}"

    mkdir -p "$bin_dir" || err "could not create ${bin_dir}"
    # Install via temp-then-rename so a concurrent koi keeps running until the swap.
    chmod +x "$extracted"
    if ! mv -f "$extracted" "${bin_dir}/${BIN_NAME}" 2>/dev/null; then
        err "could not write to ${bin_dir} (set KOI_INSTALL_DIR, or re-run with sudo for a system path)"
    fi

    printf '\n'
    say "koi ${version} installed → ${bin_dir}/${BIN_NAME}"
    printf '\n'

    # Never leave the user at a blank prompt: show it actually runs (fast, local,
    # always exits 0). Call by full path — the current shell may not have it on PATH yet.
    "${bin_dir}/${BIN_NAME}" status 2>/dev/null || true
    printf '\n'

    # PATH guidance, unless the dir is already reachable.
    if [ -z "${KOI_NO_MODIFY_PATH:-}" ]; then
        case ":${PATH}:" in
            *":${bin_dir}:"*) ;;
            *) say "add to PATH:        export PATH=\"${bin_dir}:\$PATH\"" ;;
        esac
    fi

    say "see your network:   ${BIN_NAME} mdns discover     # instant, no daemon"
    say "run as a service:   sudo ${BIN_NAME} install      # then just run: ${BIN_NAME}"
    say "verify this build:  gh attestation verify ${archive} --repo ${REPO}   (optional)"
}

main "$@"
