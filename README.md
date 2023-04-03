# tail2

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install rust src `rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

## Build Userspace

```bash
cargo build
```

## Run

```bash
npm run watch
```

## Flamegraph

```bash
flamegraph --root -- target/release/tail2
```

## Troubleshooting

Error: `"failed to create map"`
Solution: ```ulimit -l unlimited```

print type sizes:
```bash
cargo rustc --features aarch64 -- -Zprint-type-sizes
```

## License

TODO: