import struct
import tempfile
import unittest
from pathlib import Path

from garuda_v3.pcap_reader import packets
from garuda_v3.pcap_tail_clean import clean


class PcapTailCleanTests(unittest.TestCase):
    def make_pcap(self, path: Path, truncated: bool):
        global_header = b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, 65535, 101)
        # Minimal raw IPv4 UDP packet, 20 byte IP + 8 byte UDP.
        ip = bytearray(28)
        ip[0] = 0x45
        ip[2:4] = struct.pack('!H', 28)
        ip[8] = 64
        ip[9] = 17
        ip[12:16] = b'\x0a\x00\x00\x01'
        ip[16:20] = b'\x0a\x00\x00\x02'
        ip[20:24] = struct.pack('!HH', 1234, 53)
        ip[24:28] = struct.pack('!HH', 8, 0)
        record = struct.pack('<IIII', 1, 0, len(ip), len(ip)) + bytes(ip)
        tail_header = struct.pack('<IIII', 2, 0, 100, 100)
        path.write_bytes(global_header + record + (tail_header + b'abc' if truncated else b''))

    def test_clean_drops_only_incomplete_eof_record(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            source = td / 'source.pcap'
            output = td / 'clean.pcap'
            audit = td / 'audit.json'
            self.make_pcap(source, truncated=True)
            result = clean(source, output, audit)
            self.assertEqual(result['complete_records'], 1)
            self.assertEqual(result['removed_tail']['reason'], 'incomplete_record_payload')
            decoded = list(packets(output, max_packets=10))
            self.assertEqual(len(decoded), 1)
            self.assertEqual(decoded[0]['dport'], 53)
            self.assertTrue(audit.exists())

    def test_complete_file_stays_complete(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            source = td / 'source.pcap'
            output = td / 'clean.pcap'
            audit = td / 'audit.json'
            self.make_pcap(source, truncated=False)
            result = clean(source, output, audit)
            self.assertIsNone(result['removed_tail'])
            self.assertEqual(len(list(packets(output, max_packets=10))), 1)


if __name__ == '__main__':
    unittest.main()
