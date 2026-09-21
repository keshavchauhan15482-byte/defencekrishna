"""Pre-external-access label correction for V92 development hardening.

V91's RT-IoT2022 helper used prefix matching for benign MQTT traffic, which can also
match an attack label such as MQTT_DDoS_Connect_Flood. V92 has not accessed ToN-IoT at
the time of this correction. This wrapper changes only the already-exposed RT-IoT2022
development labels to the dataset's explicit benign traffic names; all V92 selection,
threshold, feature and sealed-test logic remains in the base module.
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from . import v92_toniot_external_one_shot as base


BENIGN_RT_LABELS = {"mqttpublish", "thingspeak", "wiprobulb"}


def load_rtiot_canonical_fixed(path: Path):
    df = pd.read_csv(path, low_memory=False)
    m = {base.norm(c): c for c in df.columns}
    c_label = base.pick(m, "Attack_type", "attacktype")
    c_proto = base.pick(m, "proto", "protocol")
    c_fpk = base.pick(m, "fwd_pkts_tot", "fwdpktstot", "totfwdpkts")
    c_bpk = base.pick(m, "bwd_pkts_tot", "bwdpktstot", "totbwdpkts")
    c_fb = base.pick(m, "fwd_pkts_payload.tot", "fwdpktspayloadtot", "totlenfwdpkts")
    c_bb = base.pick(m, "bwd_pkts_payload.tot", "bwdpktspayloadtot", "totlenbwdpkts")
    c_dur = base.pick(m, "flow_duration", "flowduration", "duration")
    required = [c_label, c_proto, c_fpk, c_bpk, c_fb, c_bb]
    if any(v is None for v in required):
        raise RuntimeError(f"RT-IoT2022 canonical columns unresolved: columns={list(df.columns)}")
    label_norm = df[c_label].astype(str).str.strip().map(base.norm)
    normal = label_norm.isin(BENIGN_RT_LABELS)
    y = (~normal).astype(np.int8)
    return pd.DataFrame({
        "duration": 0.0 if c_dur is None else df[c_dur],
        "orig_bytes": df[c_fb], "resp_bytes": df[c_bb],
        "orig_pkts": df[c_fpk], "resp_pkts": df[c_bpk],
        "proto": df[c_proto], "y": y,
    })


def main():
    base.load_rtiot_canonical = load_rtiot_canonical_fixed
    base.main()


if __name__ == "__main__":
    main()
