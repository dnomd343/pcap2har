# pcap2har

Convert packet captures and TLS key logs into HAR files using TShark. Supports HTTP/1.x, HTTP/2, and HTTP/3.

## Requirements

- Python 3.14 or newer and [uv](https://docs.astral.sh/uv/).
- [TShark](https://www.wireshark.org/) installed and available on `PATH`, or supplied with `--tshark`.
- For the capture workflow below: macOS and Google Chrome.

Run the following commands from the repository root.

## Capture Chrome traffic on macOS

### 1. Launch Chrome with TLS key logging

```sh
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --user-data-dir="$PWD/profile" \
  --ssl-key-log-file="$PWD/tls-keys.log" \
  --no-default-browser-check \
  --no-first-run
```

This opens a separate Chrome profile and writes TLS session secrets to `tls-keys.log`. Keep this browser open; wait until capture starts before visiting the target website.

### 2. Find the Chrome network process

In another terminal, run:

```sh
ps -axo pid,ppid,command | rg 'network\.mojom\.NetworkService'
```

Choose the network service belonging to the Chrome instance above. The first column is its PID; use the parent PID and command line to distinguish it from other Chrome instances.

### 3. Capture packets

Replace `12345` with the network service PID:

```sh
sudo /usr/sbin/tcpdump -i pktap,all -s 0 -w traffic.pcapng -Q 'pid = xxx'
```

Browse the target website, then press **Ctrl+C** in the capture terminal to stop. The `pktap,all` interface and PID filter are macOS-specific; `-s 0` captures full packets.

## Convert to HAR

```sh
uv run pcap2har --pcap traffic.pcapng --keys tls-keys.log -o capture.har
```

`uv run` installs the project dependencies automatically. The command writes `capture.har` and prints its absolute path. An existing output file is replaced.

| Option | Description |
| --- | --- |
| `--pcap` | Input `.pcap` or `.pcapng` file. |
| `--keys` | TLS key log from the captured browser session. |
| `-o`, `--out` | Output HAR file. |
| `--tshark` | Optional path to the TShark executable. |

If TShark is not on `PATH`, provide its location explicitly:

```sh
uv run pcap2har --pcap traffic.pcapng --keys tls-keys.log -o capture.har \
  --tshark /Applications/Wireshark.app/Contents/MacOS/tshark
```

For missing requests, check that the selected PID is correct, the key log is populated, and capture began before the connections were established. Protocol decoding depends on your TShark version and the completeness of the capture.

Treat packet captures, TLS key logs, and HAR files as sensitive: they may expose credentials, cookies, and request or response bodies.
