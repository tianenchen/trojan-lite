# trojan-lite

Trojan-lite is a lightweight Troajn protocol implementation. At the same time it is my personal network programming practice. It has these properties:

- TCP and UDP supported
- Ipv4 and Ipv6 supported
- DoT(DNS over TLS)
- user management API

The current version of trojan-lite is experimental. Tests, bug reports, user feedback, and other experiments are all welcome at this stage.

## Build

```bash
cargo build --release
```

## Usage

```bash
# Move to the executable file directory
cd target/release

# Create self signed certificate
openssl req -x509 -nodes -days 1825 -newkey rsa:4096 -keyout server.key -out server.crt

# Run server
RUST_LOG=info ./trojan-lite-server 0.0.0.0:20001 yourpassword1 --cert server.crt --key server.key --threads 4

# For more details you can use `--help` option
./trojan-lite-server --help
```

Also you can use trojan-lite as a lib `[WIP]`

```toml
trojan-lite = { version = "0.1" , default-features=false }
```

## Tools

You can build with `'--features perf'` option to build a trojan-perf tool.

Use `trojan-perf` to test loopback throughput:

```bash
./trojan-perf --thread 2 --user yourpassword
```

## License

trojan-lite is licensed under Apache-2.0.
