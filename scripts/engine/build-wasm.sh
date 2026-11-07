#!/usr/bin/env bash
# Build the two WASM artifacts and smoke-test them (skills/wasm-hosts).
#
#   browser   wasm32-unknown-unknown  crates/opentide-wasm (wasm-bindgen)
#   wasi      wasm32-wasip1           crates/opentide-lsp (the CLI, for vscode.dev)
#
# tree-sitter, the grammars, and the ES|QL scanner are C, so both need a
# wasm C toolchain and libc: wasi-sdk, pinned below. The browser artifact
# links wasi-sdk's libc.a and answers its syscalls inside the module
# (crates/opentide-wasm/src/libc_syscalls.rs), so it imports nothing but
# wasm-bindgen's glue. WASI_SDK_PATH reuses an existing install.
#
#   scripts/build-wasm.sh [browser] [wasi]    default: both
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
targets=("$@")
[[ ${#targets[@]} -gt 0 ]] || targets=(browser wasi)

version=25.0
digest=52640dde13599bf127a95499e61d6d640256119456d1af8897ab6725bcf3d89c
if [[ -z "${WASI_SDK_PATH:-}" ]]; then
  cache="$root/target/wasi-sdk"
  WASI_SDK_PATH="$cache/wasi-sdk-$version-x86_64-linux"
  if [[ ! -x "$WASI_SDK_PATH/bin/clang" ]]; then
    mkdir -p "$cache"
    curl -fsSL -o "$cache/wasi-sdk.tar.gz" \
      "https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${version%%.*}/wasi-sdk-$version-x86_64-linux.tar.gz"
    echo "$digest  $cache/wasi-sdk.tar.gz" | sha256sum -c -
    tar -xzf "$cache/wasi-sdk.tar.gz" -C "$cache"
  fi
fi
sysroot="$WASI_SDK_PATH/share/wasi-sysroot"

for target in "${targets[@]}"; do
  case "$target" in
    browser)
      rustup target add wasm32-unknown-unknown >/dev/null
      # wasi-libc's headers describe the libc linked below; tree-sitter's C
      # needs __wasi__ to take its non-POSIX paths. libc.a is appended to
      # RUSTFLAGS, not CARGO_TARGET_*_RUSTFLAGS: Cargo ignores the target
      # variable whenever RUSTFLAGS is set (CI sets -Dwarnings).
      CC_wasm32_unknown_unknown="$WASI_SDK_PATH/bin/clang" \
      AR_wasm32_unknown_unknown="$WASI_SDK_PATH/bin/llvm-ar" \
      CFLAGS_wasm32_unknown_unknown="-isystem $sysroot/include/wasm32-wasip1 -D__wasi__" \
      RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=$sysroot/lib/wasm32-wasip1/libc.a" \
        cargo build --release -p opentide-wasm --target wasm32-unknown-unknown
      wasm="$root/target/wasm32-unknown-unknown/release/opentide_wasm.wasm"
      node "$root/scripts/wasm-smoke.mjs" imports "$wasm"
      if command -v wasm-bindgen >/dev/null 2>&1; then
        out="$root/target/wasm-bindgen"
        wasm-bindgen --target nodejs --out-dir "$out" "$wasm"
        node "$root/scripts/wasm-smoke.mjs" browser "$out/opentide_wasm.js"
      else
        echo "wasm-bindgen not installed; highlight() not exercised"
      fi ;;
    wasi)
      rustup target add wasm32-wasip1 >/dev/null
      CC_wasm32_wasip1="$WASI_SDK_PATH/bin/clang" \
      AR_wasm32_wasip1="$WASI_SDK_PATH/bin/llvm-ar" \
      CFLAGS_wasm32_wasip1="--sysroot=$sysroot" \
        cargo build --release -p opentide-lsp --target wasm32-wasip1
      node "$root/scripts/wasm-smoke.mjs" wasi "$root/target/wasm32-wasip1/release/opentide-lsp.wasm" ;;
    *)
      echo "unknown target: $target (browser or wasi)"
      exit 2 ;;
  esac
done
