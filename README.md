# nfs-top

Ratatui-inspired Linux NFS client monitor for `/proc/*` data sources.

## Build and run

- `cargo run --release`
- `cargo run --release --no-default-features --features=termion`
- `cargo run --release --no-default-features --features=termwiz`

## Portable build (Makefile)

- `make portable-host`
  - Builds a static musl binary for the current Linux CPU architecture.
- `make portable TARGET=x86_64-unknown-linux-musl`
  - Builds one target (uses `cargo-zigbuild` when available).
- `make portable-all`
  - Builds static binaries for:
    - `x86_64-unknown-linux-musl`
    - `aarch64-unknown-linux-musl`
    - `armv7-unknown-linux-musleabihf`

Artifacts are placed in `dist/` as `nfs-top-<target>`.

## Packages

- `make rpm` — Build an `.rpm` for the host arch (set `RPM_TARGET=<triple>`
  to cross-package). Output: `dist/nfs-top-<version>-<release>.<arch>.rpm`.
  Requires `rpmbuild` (`dnf install rpm-build`).
- `make rpm-all` — Build `.rpm`s for all targets.
- `make deb` / `make deb-all` — Equivalent for `.deb`. Works on RHEL hosts
  via an `ar`+`tar` fallback when `dpkg-deb` isn't installed.

Override per-package metadata with `PKG_LICENSE=...`, `PKG_MAINTAINER=...`,
`RPM_RELEASE=...`, etc. See `make help`.

## CLI

- `--interval-ms <N>` sampling interval, default `1000`
- `--history <N>` rolling samples for charts, default `120`
- `--mount <substring>` initial mount filter
- `--mp <substring>` alias for `--mount`
- `--sort <read|write|ops|rtt|exe|mount|nconnect|obsconn>`
- `--units <auto|m|g|t>`
- `--no-dns`
- `--raw-dump <path>` dump one parsed snapshot and exit
- `--remote-ports <csv>` default `2049,20049`
- `--backend <auto|proc|ebpf>` latency backend selector, default `auto`
  (`auto` uses eBPF when built in and attach succeeds, else `/proc`; `proc`
  forces `/proc` only; `ebpf` requires the eBPF backend)

## Keybinds

- `q` quit
- `h/l` or `Left/Right` change tab
- `j/k` or `Up/Down` select mount
- `space` pause/resume
- `r` reset baseline/history
- `s` cycle sort
- `p` cycle trends mode (`all`, `avg`, `p90`, `p95`, `p99`)
- `?` help tab
- `a/m/g/t` units mode
- `+/-` adjust local UI interval indicator

## Data sources

- `/proc/self/mountstats`
- `/proc/mounts` (fallback `/etc/mtab`)
- `/proc/net/rpc/nfs`
- `/proc/net/tcp` + `/proc/net/tcp6`

## Limitations

- Connection attribution to mounts is heuristic and primarily based on `addr=` and DNS resolution of `server:/export` hostnames.
- Per-op timing fields vary across kernel/NFS versions, so some latency cells can show `-` when unavailable.
- PID/inode ownership correlation is not enforced in this MVP; observed connections are remote-IP based.

## Future work

- **Richer packaging.** The `.deb` target is functional but minimal
  (control file + binary). A future pass could add proper
  `/usr/share/doc/<pkg>/copyright`, a `man` page, shell completions, and
  signed releases for both `.deb` and `.rpm`.

## eBPF latency backend (optional)

Builds with `--features=ebpf` enable a kernel-side latency enricher that
attaches BPF programs to the NFS-client tracepoints
`nfs_initiate_{read,write,commit}` and `nfs_{readpage,writeback,commit}_done`.
Per-RPC latencies are folded into log2-ns histograms, snapshotted each
tick (no map reset), and surfaced on a new **Hist** tab as p50, p90,
p99, p99.9, p99.99, p99.999, and max — with a distribution-shape
sparkline driven by raw bucket counts (so bimodal, long-tail, and
single-peak workloads are visually distinguishable, not collapsed
into one rank-encoded glyph).

The `/proc` sampler is unchanged. eBPF data is purely additive: attach
failures (no `CAP_BPF`, no BTF, kernel too old, verifier rejection) are
routed through the existing status-bar `warn:` channel and the `/proc`
path keeps running.

### Build and run

```sh
cargo build --release --features=ebpf
sudo ./target/release/nfs-top
# or grant capability once and run unprivileged:
sudo setcap cap_bpf,cap_sys_resource=ep ./target/release/nfs-top
./target/release/nfs-top
```

A standalone smoke harness verifies the BPF path independently of the
TUI — useful for CI or for triaging "is the kernel side actually
working on this host":

```sh
cargo build --features=ebpf --example bpf_smoke
sudo ./target/debug/examples/bpf_smoke
```

It generates synthetic NFS read traffic against any mounted NFS export,
dumps per-tick latency snapshots, and exits 0 on success.

### Requirements

- Linux 5.14+ (RHEL 9, Ubuntu 22.04+, Debian 12+) with BTF in
  `/sys/kernel/btf/{vmlinux,nfs}`.
- `clang` at build time (`libbpf-cargo` invokes it for the BPF object).
- `CAP_BPF` and `CAP_SYS_RESOURCE` at runtime.
- `libbpf` is vendored via `libbpf-sys`; no system `libbpf-devel` needed.

### Implemented

- READ, WRITE, COMMIT probes covering both NFSv3 and NFSv4 RPC paths.
- Snapshot-and-diff per tick — no map reset, so no read+delete race window.
- Per-op p50..p99.999 + max via log2 histograms.
- Hist tab with percentile table and a real distribution sparkline.
- **Runtime backend selector** (`--backend=auto|proc|ebpf`). `proc` forces
  the `/proc` path even on an eBPF-enabled build; `ebpf` insists on the eBPF
  backend (and errors at startup if the binary was built without the
  feature); `auto` (default) prefers eBPF when available and silently falls
  back to `/proc`.

### Not yet implemented

- **Per-mount split.** Histograms aggregate across all NFS mounts on the
  host. Splitting by `s_dev` requires walking
  `nfs_pgio_header → inode → i_sb` from BPF and is the next step.
- **SUNRPC wire-RTT layer** (the wire-vs-client-stack diagnostic from
  the design doc).
- **Outlier ringbuf** (`--emit-outliers=<ms>`).
- **v4 metadata ops** (GETATTR, LOOKUP, OPEN, etc.) — only the
  read/write/commit pgio path is instrumented today.

### Troubleshooting

- Status bar shows `warn: ebpf disabled: …` → `Enricher::try_new()`
  failed at startup. The error is the actual cause; common ones are
  missing `CAP_BPF`, `/sys/kernel/btf/nfs` not readable as the running
  uid, or verifier rejection (check `dmesg`).
- Hist tab shows "eBPF probes attached — waiting for NFS RPC traffic"
  → the kernel side is healthy, there just hasn't been an init/done
  event since the last tick. Drive load with
  `cat /mnt/<nfs>/some-file > /dev/null`.
- Probes don't fire for cached reads — NFS read tracepoints only fire
  when the kernel actually issues an RPC. Drop the page cache or use
  `O_DIRECT` to force wire traffic.
