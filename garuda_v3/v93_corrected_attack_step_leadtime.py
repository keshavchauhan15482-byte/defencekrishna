"""V93 corrected CICAPT attack-step onset lead-time audit.

V93 is the release namespace for the corrected history-window-end timing protocol.
The implementation was first developed in ``v92_corrected_attack_step_leadtime``;
V92 is now reserved by the release evidence pack for the ToN-IoT first external
stress test, so this wrapper removes the version-name collision without changing
the frozen timing/evaluation mathematics.

Claim boundary: attack-step onset timing only against the commit-pinned,
non-publisher-verified recovered timeline. This is not verified incident,
successful-compromise, pre-compromise, or production zero-day evidence.
"""
from __future__ import annotations

from . import v92_corrected_attack_step_leadtime as _impl

PROTOCOL_VERSION = "V93-history-end-attack-step-onset-v1"

# Re-export the audited helpers so tests and downstream tooling have one stable
# release namespace while preserving the already-reviewed implementation.
prediction_issue_times = _impl.prediction_issue_times
group_event_onsets = _impl.group_event_onsets
onset_audit = _impl.onset_audit
bootstrap_median_ci = _impl.bootstrap_median_ci
lead_summary = _impl.lead_summary
capture_catalogue_contract = _impl.capture_catalogue_contract


def main():
    # The underlying main reads PROTOCOL_VERSION at runtime. Override only the
    # protocol identifier; all data, split, threshold, timing, and leakage logic
    # remains byte-for-byte the audited corrected implementation.
    _impl.PROTOCOL_VERSION = PROTOCOL_VERSION
    _impl.main()


if __name__ == "__main__":
    main()
