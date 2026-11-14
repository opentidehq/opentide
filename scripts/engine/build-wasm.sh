#!/usr/bin/env bash
# Build the two WASM artifacts and smoke-test them (.agents/skills/wasm-hosts).
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
#   cli       wasm32-wasip1           the opentide command line (opentide-cli's binary,
#                                     without its terminal UI), for the VS Code extension's
#                                     WASI host: optimised with wasm-opt and held to a size
#
#   scripts/engine/build-wasm.sh [browser] [wasi] [cli] [clippy]    default: browser wasi
#
# `clippy` lints the code only these targets compile (libc_syscalls.rs, the
# wasip1 paths of opentide-lsp), which the workspace's native clippy run cannot
# see, with the same C toolchain and -D warnings.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
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
      node "$root/scripts/engine/wasm-smoke.mjs" imports "$wasm"
      if command -v wasm-bindgen >/dev/null 2>&1; then
        out="$root/target/wasm-bindgen"
        wasm-bindgen --target nodejs --out-dir "$out" "$wasm"
        node "$root/scripts/engine/wasm-smoke.mjs" browser "$out/opentide_wasm.js"
      else
        echo "wasm-bindgen not installed; highlight() not exercised"
      fi ;;
    wasi)
      rustup target add wasm32-wasip1 >/dev/null
      CC_wasm32_wasip1="$WASI_SDK_PATH/bin/clang" \
      AR_wasm32_wasip1="$WASI_SDK_PATH/bin/llvm-ar" \
      CFLAGS_wasm32_wasip1="--sysroot=$sysroot" \
        cargo build --release -p opentide-lsp --target wasm32-wasip1
      # Node 22's fast WASI calls (fd_write, path_open) can start a garbage
      # collection inside the call, which segfaults once the instance holds
      # enough memory; the lsp-client wasi transport documents the same flag.
      node --no-turbo-fast-api-calls "$root/scripts/engine/wasm-smoke.mjs" wasi "$root/target/wasm32-wasip1/release/opentide-lsp.wasm" ;;
    cli)
      # The command line under WASI (ADR 0007's amendment): no terminal UI, no
      # threads; requests to the network fail with network_unavailable.
      rustup target add wasm32-wasip1 >/dev/null
      # The version the module reports: the release's (OPENTIDE_VERSION, as
      # the release train sets it), else a development one of the shape an
      # editable install of the Python package reports (`0.1.devN+g<sha>`),
      # never the engine crates' own.
      OPENTIDE_VERSION="${OPENTIDE_VERSION:-0.1.dev0+wasi}" \
      CC_wasm32_wasip1="$WASI_SDK_PATH/bin/clang" \
      AR_wasm32_wasip1="$WASI_SDK_PATH/bin/llvm-ar" \
      CFLAGS_wasm32_wasip1="--sysroot=$sysroot -Oz" \
        cargo build --locked --profile wasi -p opentide-cli --bin opentide-cli \
          --no-default-features --target wasm32-wasip1
      built="$root/target/wasm32-wasip1/wasi/opentide-cli.wasm"
      out="$root/target/wasm32-wasip1/wasi/opentide.wasm"
      # OPENTIDE_WASM_OPT=1: binaryen's wasm-opt as well. Measured on this
      # module it saves about 2% of the gzip size (6.85 to 6.70 MB) for
      # minutes of CPU, so it is the release's step, not every CI run's.
      # binaryen is pinned; npm's build of it needs no install. The
      # stripped module has no target_features section, so the features are
      # named: those rustc enables for wasm32-wasip1 by default.
      if [[ "${OPENTIDE_WASM_OPT:-0}" == 1 ]]; then
        npx --yes --package=binaryen@132.0.0 wasm-opt -Oz \
          --enable-bulk-memory --enable-bulk-memory-opt --enable-multivalue \
          --enable-mutable-globals --enable-nontrapping-float-to-int \
          --enable-reference-types --enable-sign-ext \
          "$built" -o "$out"
      else
        cp "$built" "$out"
      fi
      raw=$(wc -c <"$out")
      gz=$(gzip -9c "$out" | wc -c)
      # The .vsix is a zip: the module's deflated size is what it adds, held
      # to the .vsix's own 15 MiB (plan §11, ADR 0007's amendment).
      budget=$((15 * 1024 * 1024))
      echo "opentide.wasm: ${raw} bytes, ${gz} bytes gzip -9 (budget ${budget} gzip)"
      if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        echo "| \`opentide.wasm\` | ${raw} B raw | ${gz} B gzip -9 | budget ${budget} B |" >>"$GITHUB_STEP_SUMMARY"
      fi
      if ((gz > budget)); then
        echo "opentide.wasm is over its size budget" >&2
        exit 1
      fi ;;
    clippy)
      rustup target add wasm32-unknown-unknown wasm32-wasip1 >/dev/null
      CC_wasm32_unknown_unknown="$WASI_SDK_PATH/bin/clang" \
      AR_wasm32_unknown_unknown="$WASI_SDK_PATH/bin/llvm-ar" \
      CFLAGS_wasm32_unknown_unknown="-isystem $sysroot/include/wasm32-wasip1 -D__wasi__" \
        cargo clippy --locked -p opentide-wasm --target wasm32-unknown-unknown --all-targets -- -D warnings
      # The library and the binary: the tests' dev-dependencies (os_pipe, through
      # trycmd) do not build for wasip1.
      CC_wasm32_wasip1="$WASI_SDK_PATH/bin/clang" \
      AR_wasm32_wasip1="$WASI_SDK_PATH/bin/llvm-ar" \
      CFLAGS_wasm32_wasip1="--sysroot=$sysroot" \
        cargo clippy --locked -p opentide-lsp --target wasm32-wasip1 --lib --bins -- -D warnings
      # The command line's WASI paths (`cfg(target_os = "wasi")`), as `cli` builds it.
      CC_wasm32_wasip1="$WASI_SDK_PATH/bin/clang" \
      AR_wasm32_wasip1="$WASI_SDK_PATH/bin/llvm-ar" \
      CFLAGS_wasm32_wasip1="--sysroot=$sysroot" \
        cargo clippy --locked -p opentide-cli --no-default-features --target wasm32-wasip1 \
          --lib --bins -- -D warnings ;;
    *)
      echo "unknown target: $target (browser, wasi, cli or clippy)"
      exit 2 ;;
  esac
done
