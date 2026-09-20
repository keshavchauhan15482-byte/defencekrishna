# V65 diagnostic baseline used for V66 engineering

V65 is not a passing release claim. It is the diagnostic that motivated the V66 stability change.

## Fresh precommitted Worms result

The Worms family/campaign was frozen before Worms model scores were inspected. Test support was 21 positive windows and 617 clean negatives for every outer seed.

| Seed | TP | FN | FP | TN | Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|
| 42 | 21 | 0 | 0 | 617 | 100.00% | 0.000% |
| 43 | 21 | 0 | 0 | 617 | 100.00% | 0.000% |
| 44 | 1 | 20 | 0 | 617 | 4.76% | 0.000% |

Across the three outer seeds, mean recall was **68.25%** with **54.99 percentage-point sample SD**. The alert gate therefore failed. A 100% point estimate from seeds 42 or 43 must not be presented as a perfect detector.

For 21/21 detections, the two-sided Wilson 95% recall interval is approximately **84.54% to 100%**. For 1/21 detections it is approximately **0.85% to 22.67%**. For 0 false positives among 617 negatives, the Wilson 95% FPR upper bound is approximately **0.619%**. The conservative all-seed view therefore fails because of seed 44.

## Engineering interpretation

The V65 component audit showed strong outer-seed sensitivity in the nonlinear transfer component. V66 removes avoidable classifier RNG by averaging a fixed three-member ExtraTrees ensemble and changes development-only fusion selection to prioritize all-seed consistency. Worms is considered inspected development evidence from V66 onward and is not reused as a fresh reserve.

The next reserve, Fuzzers, is frozen before any Fuzzers model score is computed. V66 will report exact confusion counts and Wilson intervals whether it passes or fails.
