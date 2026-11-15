# Independent development data: AIT Netflow v2

Publisher: https://zenodo.org/records/13168643 (AIT Netflow Data Set, version 2).
This is synthetic enterprise-testbed network traffic, not organic customer traffic.
It is a separate development-source investigation; no existing benchmark is replaced.

## Acquired and checked

The fox archive has 25,870,023 bytes and matches the publisher MD5
`d3024ef6033fbd45982464f6b6f50984`. SHA256 is
`e2bfacdfe9822109c807300f941d0a0c9fa1b370bcf2822fd12f27ed23928381`.
The machine-readable audit is `ait_fox_readiness.json`.

351,908 exported records were audited. These are NOT independent attack incidents;
overlapping sensors and repeated attack steps must not inflate evaluation support.
The source includes 14,668 records labelled `data exfiltration`, 13,901 `service_scan`,
61 `online_cracking`, but only TWO `upload_rce_shell` records. These are publisher
behaviour labels, not a validated five-tactic forecast target. No inferred MITRE
stage mapping, fabricated stage intervals or silent unknown-to-benign conversion
is introduced by this audit.

## Consequence

More total records do not solve rare-stage/campaign support. This source may help
binary temporal and exfiltration development, but cannot by itself establish five
supported tactics, verified successful-compromise lead time or cross-domain quality.
No model was trained and no prediction metric is produced by this audit.

The code allows only development candidates fox/harrison/russellmitchell/santos/shaw.
Wardbeck/wheeler/wilson are reserved from THIS audit and remain undecoded here;
global prior exposure must still be checked before claiming any fresh final test.
The publisher checksum pins the acquired bytes. MD5 is a publisher integrity check,
not a security signature; SHA256 is also recorded. Publisher authenticity depends
on the original source, not merely matching a local hash.

## Reproduce

```sh
python -m garuda_v3.ait_source_audit --campaign fox \
  --cache /path/to/new-local-cache --output /path/to/new-audit.json
python -m unittest garuda_v3.tests.test_ait_source_audit -v
```

CSV schema/label ambiguity, bad checksums and oversized archives fail closed.
ZIP contents are streamed as data; they are not extracted or executed. Missing
labels remain explicitly unknown. Output reports are immutable. No runtime bundle,
model weight, historical test metric or containment authority is changed.
