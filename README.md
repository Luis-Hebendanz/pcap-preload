## PCAP Preload
Build the shared library:
```bash
cargo build --release
```

Or if Nix is installed. And flakes is enabled:
```bash
nix build .
```

Example usage:
```bash
PCAP_LOG_FILE=peer_512.pcap LD_PRELOAD=libpcap_preload.so ./student_peer.elf 0 10 100
```


