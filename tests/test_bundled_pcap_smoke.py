"""Publisher-hash check -> audited preparation -> real four-horizon inference."""
import tempfile
from pathlib import Path
import numpy as np

from garuda_v3.latest_state_runtime import LatestStateForecastService
from garuda_v3.pcap_packaging import prepare

ROOT = Path(__file__).resolve().parents[1]


def main():
    runtime = LatestStateForecastService()
    captures = sorted((ROOT / 'datasets/ids2018/raw').glob('*.pcap'))
    assert len(captures) == 4, 'Expected four explicit bundled captures'
    with tempfile.TemporaryDirectory() as td:
        for capture in captures:
            derivative = Path(td) / capture.name
            audit = prepare(capture, derivative)
            assert audit['usable'], audit
            result = runtime.analyze_pcap(derivative.read_bytes())
            assert result['status'] == 'SUPPORTED_STATE_FORECAST', result
            assert [p['horizon_seconds'] for p in result['trajectory']] == [10,20,30,40]
            assert all(np.isfinite(p['state_vector']).all() for p in result['trajectory'])
            assert result['risk_probability'] is None and result['mitre_stage'] is None
            assert not result['automatic_containment']
            print(capture.name, 'PASS', 'decoded packets:', result['ingestion']['decoded_ipv4_packets'])


if __name__ == '__main__': main()
