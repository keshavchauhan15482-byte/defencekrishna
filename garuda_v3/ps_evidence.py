"""Expose the complete published comparison, without mixing experiment lanes."""
import hashlib
import re
from pathlib import Path

REPORT = Path(__file__).resolve().parents[1] / 'docs/release/v88_final_independent_source/RESULTS.md'


def published_comparison(path=REPORT):
    path = Path(path)
    body = path.read_text(encoding='utf-8')
    rows = {}
    for title, key in [('Precision', 'precision'), ('Recall', 'recall'), ('F1', 'f1'), ('False-positive rate', 'fpr')]:
        match = re.search(r'^\|\s*' + re.escape(title) + r'\s*\|([^|]+)\|([^|]+)\|', body, re.M)
        if not match:
            raise ValueError('Complete published comparison unavailable: ' + key)
        values = []
        for cell in match.groups():
            number = re.fullmatch(r'\s*\*{0,2}([0-9]+(?:\.[0-9]+)?)%\*{0,2}\s*', cell)
            if not number or not 0 <= float(number[1]) <= 100:
                raise ValueError('Invalid published percentage')
            values.append(float(number[1]) / 100)
        rows[key] = dict(zip(('logistic_regression', 'garuda'), values))
    return dict(schema='published-comparison-v1', metrics=rows,
                source='docs/release/v88_final_independent_source/RESULTS.md',
                source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                scope='V88 UNSW-NB15 two episodes; Garuda three-seed macro, same-input LR',
                recorded_published_evidence=True, independently_reproduced_by_this_endpoint=False,
                live_model_metrics=False, five_stage_forecast_validation=False,
                automatic_containment=False)
