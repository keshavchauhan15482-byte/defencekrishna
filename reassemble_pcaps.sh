#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="$DIR/datasets/ids2018/fresh_holdout"
echo "Reassembling datasets/ids2018/fresh_holdout/Thursday-15-02-2018.pcap..."
cat "$TARGET_DIR"/Thursday-15-02-2018.pcap.part_* > "$TARGET_DIR"/Thursday-15-02-2018.pcap
echo "Reassembling datasets/ids2018/fresh_holdout/clean/Thursday-15-02-2018.pcap..."
cat "$TARGET_DIR"/clean/Thursday-15-02-2018.pcap.part_* > "$TARGET_DIR"/clean/Thursday-15-02-2018.pcap
echo "Verifying SHA256..."
cd "$DIR"
shasum -a 256 -c << 'HASH_EOF'
a9f4b689a4fd4b15e2efc77b23c8a5ac4e0871967258c0985cd718558f8a1c99  datasets/ids2018/fresh_holdout/Thursday-15-02-2018.pcap
e014495a36764d766b5812b126c9c3f7f18795343dbc79ee07d0073585d64e53  datasets/ids2018/fresh_holdout/clean/Thursday-15-02-2018.pcap
HASH_EOF
echo "Reassembly complete and verified!"
