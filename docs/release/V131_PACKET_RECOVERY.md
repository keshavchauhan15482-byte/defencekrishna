# V131 packet recovery and independent sensor prerequisites

This recovery converts four bundled CIC-IDS2018 raw PCAPs to one 34-feature,
10-second service graph contract. The source hashes are checked against the
existing extraction manifests. Three fixed seeds, nonoverlapping 80s histories
and 40s targets, separate campaign splits, and state-first training replace the
failed legacy risk experiment. The risk head is not fitted if development
class counts are insufficient; support is fitted on training/validation only.
The existing schedule labels are explicitly weak and all four campaigns are
consumed development sources. No new independent validation is claimed.

The release still needs independently reviewed benign/malicious timelines,
fresh unseen campaigns, validated risk/support, and correlated warning/onset
timestamps. Do not use the already consumed external holdouts as fresh tests.
An authorized independent Linux network sensor is required for live packet
telemetry. Existing Vercel/Render free services do not expose the Vercel ingress
packet stream. The repository's existing sensor_runner supports an explicit
owned interface and private sensor token; do not install it on an unapproved
interface, use a shared platform interface, or fabricate heartbeat records.
No paid compute provisioned. The current 21-feature host checkpoint and this
34-feature service candidate are incompatible and are not interchangeable.
No automatic promotion, production inference, containment, or frontend change.

The first recovery run failed before training because a source PCAP ends in an incomplete record. The corrected run uses the existing offline `pcap_tail_clean` utility before feature extraction. It retains source SHA-256 provenance, hashes the cleaned derivative, excludes entire affected 10-second windows, and uploads integrity audits. The strict runtime parser is unchanged. No excluded window is imputed.
