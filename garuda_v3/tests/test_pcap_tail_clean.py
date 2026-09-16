import json
import struct
import tempfile
import unittest
from pathlib import Path

from garuda_v3.pcap_reader import packets
from garuda_v3.pcap_tail_clean import clean


class PcapTailCleanTests(unittest.TestCase):
    def udp_packet(self, total_length=28, captured_length=None):
        # Minimal raw IPv4 UDP packet. captured_length can intentionally truncate
        # the IP bytes while keeping the PCAP record itself structurally complete.
        ip = bytearray(28)
        ip[0] = 0x45
        ip[2:4] = struct.pack('!H', total_length)
        ip[8] = 64
        ip[9] = 17
        ip[12:16] = b'\x0a\x00\x00\x01'
        ip[16:20] = b'\x0a\x00\x00\x02'
        ip[20:24] = struct.pack('!HH', 1234, 53)
        ip[24:28] = struct.pack('!HH', 8, 0)
        return bytes(ip if captured_length is None else ip[:captured_length])

    def make_pcap(self, path: Path, truncated_tail: bool):
        global_header = b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, 65535, 101)
        ip = self.udp_packet()
        record = struct.pack('<IIII', 1, 0, len(ip), len(ip)) + ip
        # Put the incomplete tail in a different 10-second bucket. The cleaner
        # must retain bucket 0 and exclude only the affected bucket 10.
        tail_header = struct.pack('<IIII', 12, 0, 100, 100)
        path.write_bytes(global_header + record + (tail_header + b'abc' if truncated_tail else b''))

    def test_clean_excludes_window_touching_incomplete_eof_record(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            source = td / 'source.pcap'
            output = td / 'clean.pcap'
            audit = td / 'audit.json'
            self.make_pcap(source, truncated_tail=True)
            result = clean(source, output, audit)
            self.assertEqual(result['complete_records'], 1)
            self.assertEqual(result['removed_tail']['reason'], 'incomplete_record_payload')
            self.assertEqual(result['excluded_windows'], [10])
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
            self.make_pcap(source, truncated_tail=False)
            result = clean(source, output, audit)
            self.assertIsNone(result['removed_tail'])
            self.assertEqual(result['excluded_windows'], [])
            self.assertEqual(len(list(packets(output, max_packets=10))), 1)

    def test_snaplen_truncated_ipv4_excludes_entire_window(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            source = td / 'source.pcap'
            output = td / 'clean.pcap'
            audit = td / 'audit.json'
            global_header = b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, 65535, 101)

            good = self.udp_packet()
            good_record = struct.pack('<IIII', 1, 0, len(good), len(good)) + good

            # PCAP record is complete, but its IPv4 header claims 28 bytes while
            # only 24 were captured. This mirrors the real Friday-02 failure.
            bad = self.udp_packet(total_length=28, captured_length=24)
            bad_record = struct.pack('<IIII', 12, 0, len(bad), len(bad)) + bad

            # A second otherwise-valid packet in the same bad bucket proves the
            # cleaner drops the whole 10-second state, not merely the bad packet.
            same_bucket = self.udp_packet()
            same_bucket_record = struct.pack('<IIII', 13, 0, len(same_bucket), len(same_bucket)) + same_bucket
            source.write_bytes(global_header + good_record + bad_record + same_bucket_record)

            result = clean(source, output, audit)
            self.assertEqual(result['excluded_windows'], [10])
            self.assertEqual(result['complete_records_seen'], 3)
            self.assertEqual(result['complete_records'], 1)
            self.assertEqual(result['invalid_records_sample'][0]['reason'], 'truncated_ipv4_packet')
            decoded = list(packets(output, max_packets=10))
            self.assertEqual(len(decoded), 1)
            self.assertLess(decoded[0]['t'], 10)
            persisted = json.loads(audit.read_text())
            self.assertEqual(persisted['excluded_windows'], [10])


if __name__ == '__main__':
    unittest.main()
