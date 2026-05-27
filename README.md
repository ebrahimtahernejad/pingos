# pingos

TCP-over-ICMP tunnel. A clean-room Rust rewrite of the TCP-forward subset of
[pingtunnel](https://github.com/esrrhs/pingtunnel), built event-driven from
the ground up to eliminate the polling hiccups in the Go original.

- **transport**: raw or unprivileged DGRAM ICMP
- **encryption**: ChaCha20-Poly1305 (BLAKE3-derived key from password)
- **reliability**: per-connection sliding window, SRTT/RTO retransmit, cumulative ACK
- **compression**: optional LZ4 per frame
- **FEC**: optional Reed-Solomon over packet groups
- **config**: TOML files (`/etc/pingos/{server,client}.toml`) with CLI override

## Install (Linux)

```bash
curl -fsSL https://github.com/EbrahimTahernejad/pingos/releases/latest/download/install.sh | sudo bash
```

A wizard walks you through server-vs-client, password, compression, FEC, and
ports. It downloads the right musl binary for your arch (x86_64 or aarch64),
writes `/etc/pingos/<role>.toml`, drops a `pingos.service` unit, and
`systemctl enable --now`s it.

Non-interactive (CI/automation):

```bash
PINGOS_NONINTERACTIVE=1 \
PINGOS_ROLE=server PINGOS_PASSWORD='hunter2' \
PINGOS_COMPRESSION=lz4 PINGOS_FEC=8:2 \
curl -fsSL https://github.com/EbrahimTahernejad/pingos/releases/latest/download/install.sh | sudo bash
```

Dry-run mode (`PINGOS_DRY_RUN=1`) shows what would happen without touching the system.

## Run manually

```bash
# server
sudo pingos server --bind 0.0.0.0 -p secret --compression lz4 --fec 8:2

# client
sudo pingos client -l :4455 -s tunnel.example.com -t target.host:443 -p secret --compression lz4 --fec 8:2

# Or from a config file:
sudo pingos server --config /etc/pingos/server.toml
sudo pingos client --config /etc/pingos/client.toml
```

A reference config lives at [docker/configs/server.toml](docker/configs/server.toml)
and [docker/configs/client.toml](docker/configs/client.toml).

## Build from source

```bash
git clone https://github.com/EbrahimTahernejad/pingos.git
cd pingos
cargo build --release
./target/release/pingos --help
```

## Tests

```bash
cargo test                    # unit + integration tests (no ICMP needed)
./scripts/docker-smoke.sh     # full Linux end-to-end with docker compose
```

## Releases

Releases are cut automatically when `version` in `Cargo.toml` bumps on `main`.
The workflow at [.github/workflows/release.yml](.github/workflows/release.yml)
builds statically-linked musl binaries for x86_64 and aarch64 and publishes
them along with the install script.

## License

MIT.
