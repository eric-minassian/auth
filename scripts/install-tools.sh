#!/usr/bin/env bash
# Installs the pinned verification and test tools (Linux x86_64). Every
# download is checked against a SHA-256 pinned here, so CI and developers run
# exactly the same tool versions.
#
#   scripts/install-tools.sh verus|kani|tamarin|emulator|all
#
# Tools go to $TOOLS_DIR (default ~/.local/opt) with launchers in $BIN_DIR
# (default ~/.local/bin). No root access is needed.
set -euo pipefail

TOOLS_DIR="${TOOLS_DIR:-$HOME/.local/opt}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$TOOLS_DIR" "$BIN_DIR"

# Keep in sync with: Cargo.toml (vstd version) and rust-toolchain.toml.
VERUS_TAG="release/0.2026.11.02.8bf68ee"
VERUS_ZIP="verus-0.2026.11.02.8bf68ee-x86-linux.zip"
VERUS_SHA256="f3a0119292df8855e4435da8130bee1873b0e6a60c306accf81a08ea687bba3c"

KANI_VERSION="0.68.0"

TAMARIN_VERSION="1.12.0"
TAMARIN_TAR="tamarin-prover-1.12.0-linux64-ubuntu.tar.gz"
TAMARIN_SHA256="201be06f469e47cff554df6ca93db8366fc2c69d70c61fcbd1370a1074b469c6"
MAUDE_TAG="Maude3.5.1"
MAUDE_ZIP="Maude-3.5.1-linux-x86_64.zip"
MAUDE_SHA256="72ed1ca87e3b3d0dfc6ee1436baf154bf04c45ff97d521bec040c5e8dfc8f92c"

EMULATOR_VERSION="1.0.353"
EMULATOR_DEB="aws-emulator_${EMULATOR_VERSION}-1_amd64.deb"
EMULATOR_SHA256="d457c3057273b5dcb2017c187c1b85fdccc1e0dcbe874455be39def857d4a2b6"

fetch() { # url sha256 output
  curl -fsSL --retry 3 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c --quiet -
}

install_verus() {
  local dir="$TOOLS_DIR/verus-${VERUS_TAG#release/}"
  if [[ ! -x "$dir/verus-x86-linux/verus" ]]; then
    local tmp; tmp="$(mktemp -d)"
    fetch "https://github.com/verus-lang/verus/releases/download/${VERUS_TAG}/${VERUS_ZIP}" "$VERUS_SHA256" "$tmp/verus.zip"
    mkdir -p "$dir" && unzip -q "$tmp/verus.zip" -d "$dir" && rm -rf "$tmp"
  fi
  ln -sf "$dir/verus-x86-linux/verus" "$BIN_DIR/verus"
  ln -sf "$dir/verus-x86-linux/cargo-verus" "$BIN_DIR/cargo-verus"
  # Verus requires its exact toolchain to be installed under its full name.
  rustup toolchain install "$(cd "$(dirname "$0")/.." && rustup show active-toolchain | cut -d' ' -f1)" --profile minimal >/dev/null
  "$BIN_DIR/verus" --version
}

install_kani() {
  if ! cargo kani --version 2>/dev/null | grep -q "$KANI_VERSION"; then
    cargo install --locked "kani-verifier@${KANI_VERSION}"
    cargo kani setup
  fi
  cargo kani --version
}

install_tamarin() {
  local dir="$TOOLS_DIR/tamarin-${TAMARIN_VERSION}"
  if [[ ! -x "$dir/tamarin-prover" ]]; then
    local tmp; tmp="$(mktemp -d)"
    fetch "https://github.com/tamarin-prover/tamarin-prover/releases/download/${TAMARIN_VERSION}/${TAMARIN_TAR}" "$TAMARIN_SHA256" "$tmp/tamarin.tgz"
    fetch "https://github.com/maude-lang/Maude/releases/download/${MAUDE_TAG}/${MAUDE_ZIP}" "$MAUDE_SHA256" "$tmp/maude.zip"
    mkdir -p "$dir/maude" && tar -xzf "$tmp/tamarin.tgz" -C "$dir" && unzip -q "$tmp/maude.zip" -d "$dir/maude" && rm -rf "$tmp"
  fi
  ln -sf "$dir/tamarin-prover" "$BIN_DIR/tamarin-prover"
  # A wrapper rather than a symlink: Maude locates prelude.maude via MAUDE_LIB.
  printf '#!/usr/bin/env bash\nexport MAUDE_LIB="%s"\nexec "%s" "$@"\n' "$dir/maude" "$dir/maude/maude" >"$BIN_DIR/maude"
  chmod +x "$BIN_DIR/maude"
  "$BIN_DIR/tamarin-prover" --version | head -1
}

install_emulator() {
  local dir="$TOOLS_DIR/aws-emulator-${EMULATOR_VERSION}"
  if [[ ! -x "$dir/opt/aws-emulator/bin/aws-emulator" ]]; then
    local tmp; tmp="$(mktemp -d)"
    fetch "https://downloads.aws.com/aws-emulator/packages/aws-emulator/LTS/${EMULATOR_DEB}" "$EMULATOR_SHA256" "$tmp/emulator.deb"
    mkdir -p "$dir" && dpkg-deb -x "$tmp/emulator.deb" "$dir" && rm -rf "$tmp"
  fi
  ln -sf "$dir/opt/aws-emulator/bin/aws-emulator" "$BIN_DIR/aws-emulator"
  "$BIN_DIR/aws-emulator" -v | head -1
}

case "${1:-}" in
  verus) install_verus ;;
  kani) install_kani ;;
  tamarin) install_tamarin ;;
  emulator) install_emulator ;;
  all) install_verus; install_kani; install_tamarin; install_emulator ;;
  *) echo "usage: $0 verus|kani|tamarin|emulator|all" >&2; exit 2 ;;
esac
