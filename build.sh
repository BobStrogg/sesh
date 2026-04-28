#!/usr/bin/env bash
# build.sh — produce platform binaries for the @bobstrogg/sesh npm package.
#
# All builds run inside Docker; no Rust toolchain is required on the host.
#
# Targets:
#   sesh-linux-x86_64     statically linked against musl
#   sesh-linux-aarch64    cross-compiled, statically linked against musl
#   sesh-darwin-x86_64    Mach-O 64-bit x86_64, cross-built with cargo-zigbuild
#   sesh-darwin-aarch64   Mach-O 64-bit arm64,  cross-built with cargo-zigbuild
#
# Usage:
#   ./build.sh                 # build all 4 targets, drop into npm/bin/
#   ./build.sh --linux-only    # skip darwin
#   ./build.sh --x86-only      # only the two x86_64 targets

set -euo pipefail
cd "$(dirname "$0")"

build_linux_x86=true
build_linux_arm=true
build_darwin_x86=true
build_darwin_arm=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --linux-only)  build_darwin_x86=false; build_darwin_arm=false; shift ;;
    --darwin-only) build_linux_x86=false;  build_linux_arm=false;  shift ;;
    --x86-only)    build_linux_arm=false;  build_darwin_arm=false; shift ;;
    --arm-only)    build_linux_x86=false;  build_darwin_x86=false; shift ;;
    -h|--help)
      sed -n '2,/^set -euo/{ s/^# *//; p }' "$0" | sed '/^$/d; $d'
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

RUST_IMAGE=rust:slim
MUSL_CROSS_IMAGE=messense/rust-musl-cross:aarch64-musl
ZIG_VERSION=0.13.0

bin_dir="$(pwd)/npm/bin"
mkdir -p "$bin_dir"

run_in_rust() { docker run --rm -v "$PWD":/work -w /work "$@"; }

if $build_linux_x86; then
  echo "==> linux-x86_64 (musl static)"
  run_in_rust "$RUST_IMAGE" bash -c '
    set -e
    apt-get update -qq >/dev/null
    apt-get install -y --no-install-recommends musl-tools -qq >/dev/null
    rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1
    cargo build --release --target x86_64-unknown-linux-musl
  '
  cp target/x86_64-unknown-linux-musl/release/sesh "$bin_dir/sesh-linux-x86_64"
fi

if $build_linux_arm; then
  echo "==> linux-aarch64 (musl static)"
  run_in_rust "$MUSL_CROSS_IMAGE" \
    cargo build --release --target aarch64-unknown-linux-musl
  cp target/aarch64-unknown-linux-musl/release/sesh "$bin_dir/sesh-linux-aarch64"
fi

if $build_darwin_x86 || $build_darwin_arm; then
  targets=()
  $build_darwin_x86 && targets+=( "x86_64-apple-darwin" )
  $build_darwin_arm && targets+=( "aarch64-apple-darwin" )
  echo "==> darwin (cargo-zigbuild): ${targets[*]}"
  docker run --rm -i -v "$PWD":/work -w /work \
      -e ZIG_VERSION="$ZIG_VERSION" \
      "$RUST_IMAGE" bash -s -- "${targets[@]}" <<'DARWIN_EOF'
set -euo pipefail
apt-get update -qq >/dev/null
apt-get install -y --no-install-recommends curl xz-utils ca-certificates -qq >/dev/null
if ! command -v zig >/dev/null 2>&1; then
  curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz" \
    | tar -xJ -C /opt
  ln -sf "/opt/zig-linux-x86_64-${ZIG_VERSION}/zig" /usr/local/bin/zig
fi
cargo install --quiet cargo-zigbuild
for t in "$@"; do rustup target add "$t" >/dev/null 2>&1; done
for t in "$@"; do cargo zigbuild --release --target "$t"; done
DARWIN_EOF
  $build_darwin_x86 && cp target/x86_64-apple-darwin/release/sesh   "$bin_dir/sesh-darwin-x86_64"
  $build_darwin_arm && cp target/aarch64-apple-darwin/release/sesh  "$bin_dir/sesh-darwin-aarch64"
fi

echo
echo "==> built:"
ls -lh "$bin_dir"
echo
echo "==> sha256:"
( cd "$bin_dir" && sha256sum * 2>/dev/null )
