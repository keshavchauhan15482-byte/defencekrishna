# V68 Real CICAPT Packet + Flow Feature Evidence

Authoritative GitHub Actions run: `35524994985` (`V68 real CICAPT packet + flow contract`). Status: **SUCCESS**.

## Scientific contract

- Hash-pinned public CICAPT-IIoT2024 network archive from `datasets/multisource/catalogue.json`.
- Both selected capture files are detected by magic bytes as **PCAPNG**, despite `.pcap` filenames.
- Production dependency-free parser reads IPv4 TCP/UDP packet fields directly.
- Audit uses the first 200,000 decoded IPv4 packets from each capture. Results apply to these bounded prefixes only.
- This is feature-ingestion evidence, not attack-recall or lead-time evidence.

## Phase 1 bounded prefix

- 200,000 decoded IPv4 packets
- 581 ten-second windows
- 4,080 bidirectional connection flows
- 189,864 TCP + 10,062 UDP packets
- 80,898 packets with payload
- 41,342 duplicate positive-payload TCP segments counted by the retransmission feature
- TTL mean 63.73354; variance 109.21486; range 1–255
- TCP-window samples 189,864; mean 9,289.55
- Payload size mean 14.32469 bytes; maximum 1,460 bytes
- Packet features, TTL, TCP window, payload, IAT and retransmission features are non-zero in all 581 windows.
- Random-port transition evidence occurs in 130/581 windows (22.375%).
- No sequential-port transition or IP-fragment event was observed in this bounded prefix; those values remain correctly zero.

## Phase 2 bounded prefix

- 200,000 decoded IPv4 packets
- 574 ten-second windows
- 4,567 bidirectional connection flows
- 184,959 TCP + 14,953 UDP packets
- 83,361 packets with payload
- 39,984 duplicate positive-payload TCP segments counted by the retransmission feature
- TTL mean 63.118015; variance 127.39421; range 1–255
- TCP-window samples 184,959; mean 9,241.96
- Payload size mean 12.863035 bytes; maximum 1,460 bytes
- Packet features, TTL, TCP window, payload, IAT and retransmission features are non-zero in all 574 windows.
- Random-port transition evidence occurs in 137/574 windows (23.868%).
- Sequential-port transition evidence occurs in 1/574 windows (0.174%).
- No IP-fragment event was observed in this bounded prefix; the fragmentation feature remains correctly zero.

## PS feature coverage

The release schema explicitly contains the requested flow and packet groups: bytes/packets/duration, TCP flags, protocol mix, bidirectional ratio, IAT mean/variance/max, TTL mean/variance, TCP window, fragmentation, payload distribution, destination-port/scan sequencing, and retransmission count/fraction.

The audit deliberately does not turn absence into a positive result: fragmentation and some rare flags/scans were zero where the real bounded capture did not contain them.
