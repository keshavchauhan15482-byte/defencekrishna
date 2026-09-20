import socket
import struct
import tempfile
import unittest
from pathlib import Path

from garuda_v3.pcap_reader import packets


def _tcp_frame(seq=100, payload=b"hello"):
    tcp = struct.pack('!HHIIBBHHH', 12000, 445, seq, 0, 0x50, 0x18, 4096, 0, 0) + payload
    ip = struct.pack(
        '!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
        socket.inet_aton('10.0.0.1'), socket.inet_aton('10.0.0.2')
    )
    return b'\0' * 12 + b'\x08\x00' + ip + tcp


def _block(block_type, body):
    pad = b'\0' * ((-len(body)) % 4)
    total = 12 + len(body) + len(pad)
    return struct.pack('<II', block_type, total) + body + pad + struct.pack('<I', total)


def fixture(path):
    shb = struct.pack('<II', 0x0A0D0D0A, 28)
    shb += struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
    shb += struct.pack('<I', 28)
    # Ethernet, snaplen 65535; no options means default microsecond timestamps.
    idb = _block(1, struct.pack('<HHI', 1, 0, 65535))
    frame = _tcp_frame()
    epb_body = struct.pack('<IIIII', 0, 0, 1_500_000, len(frame), len(frame)) + frame
    epb = _block(6, epb_body)
    Path(path).write_bytes(shb + idb + epb)


class PcapNgReaderTests(unittest.TestCase):
    def test_pcapng_magic_and_packet_fields(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'capture.pcap'  # extension intentionally misleading
            fixture(path)
            rows = list(packets(path, max_packets=10))
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertAlmostEqual(row['t'], 1.5, places=6)
            self.assertEqual(row['src'], '10.0.0.1')
            self.assertEqual(row['dst'], '10.0.0.2')
            self.assertEqual(row['protocol'], 'tcp')
            self.assertEqual(row['dport'], 445)
            self.assertEqual(row['ttl'], 64)
            self.assertEqual(row['win'], 4096)
            self.assertEqual(row['payload_len'], 5)


if __name__ == '__main__':
    unittest.main()
