"""Packet-trained local runner checks without root or real network capture."""
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from garuda_v3.inference import ForecastService
from garuda_v3.sensor_runner import (
    DEFAULT_ARTIFACTS, _capture_stream, required_capture_seconds,
)


class PacketSensorRuntimeTests(unittest.TestCase):
    def test_actual_bundled_packet_trained_model_contract(self):
        meta = ForecastService(DEFAULT_ARTIFACTS).meta
        self.assertTrue(meta["packet_features_trained"])
        self.assertEqual(meta["mode"], "host")
        self.assertEqual(meta["history"], 8)
        self.assertEqual(meta["window_seconds"], 60)
        self.assertEqual(meta["horizon"], 4)
        self.assertEqual(required_capture_seconds(meta), 600)

    def test_csv_flow_checkpoint_is_not_misrepresented_as_packet_sensor(self):
        meta = ForecastService("garuda_v3/artifacts/residual_run").meta
        with self.assertRaisesRegex(ValueError, "packet-trained HOST"):
            required_capture_seconds(meta)
        with self.assertRaises(ValueError):
            required_capture_seconds({"mode":"host","packet_features_trained":True,
                                      "history":8,"window_seconds":120})

    def test_no_shell_user_owned_bounded_pcap_stream_capture(self):
        class Proc:
            def __init__(self, command, **kwargs):
                self.cmd = command
                self.stdout = io.BytesIO(b"\xd4\xc3\xb2\xa1" + b"\0" * 64)
                self.stderr = io.BytesIO(b"tcpdump: capturing on authorized interface")
                self.returncode = 0
            def wait(self, timeout=None):
                return 0
            def poll(self):
                return 0

        made=[]
        def make(*args,**kwargs):
            made.append(args[0])
            self.assertEqual(kwargs["process_group"],0)
            self.assertNotIn("start_new_session",kwargs)
            return Proc(*args,**kwargs)

        with tempfile.TemporaryDirectory() as tmp:
            with patch("garuda_v3.sensor_runner.shutil.which",return_value="/usr/sbin/tcpdump"):
                with patch("garuda_v3.sensor_runner.subprocess.Popen",side_effect=make):
                    captured=_capture_stream("en0",Path(tmp),90,use_sudo=False)
            self.assertTrue(captured.name.endswith(".pcap.ready"))
            self.assertEqual(captured.stat().st_size,68)
            self.assertFalse(made[0][0].endswith("sh"))
            self.assertEqual(made[0][1:3],["-i","en0"])
            self.assertEqual(made[0][-3:],["-w","-","ip"])
            with self.assertRaises(ValueError):
                _capture_stream("; rm -rf /",Path(tmp),90,use_sudo=False)

    def test_tcpdump_error_is_explained_instead_of_hidden(self):
        class Proc:
            def __init__(self, command, **kwargs):
                self.stdout=io.BytesIO(b"")
                self.stderr=io.BytesIO(b"sudo: a password is required\\n")
                self.returncode=1
            def wait(self, timeout=None):
                return 1
            def poll(self):
                return 1
        with tempfile.TemporaryDirectory() as tmp:
            with patch("garuda_v3.sensor_runner.shutil.which",return_value="/usr/sbin/tcpdump"):
                with patch("garuda_v3.sensor_runner.subprocess.Popen",side_effect=Proc):
                    with self.assertRaisesRegex(RuntimeError, "sudo: a password is required"):
                        _capture_stream("en0",Path(tmp),90,use_sudo=False)
            self.assertEqual(list(Path(tmp).glob("*.pcap")),[])
            self.assertEqual(list(Path(tmp).glob("*.pcap.ready")),[])

    def test_capture_requires_explicit_interval_and_real_interface(self):
        for value in ("", "-i", "any;evil", "../../net", "x y"):
            with self.subTest(interface=value),self.assertRaises(ValueError):
                _capture_stream(value,".",600,use_sudo=False)
        with self.assertRaises(ValueError):
            _capture_stream("en0",".",30,use_sudo=False)


if __name__ == "__main__":
    unittest.main()
