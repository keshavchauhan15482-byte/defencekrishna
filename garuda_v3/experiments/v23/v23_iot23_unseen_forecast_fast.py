"""Runtime-optimized V23 development run.

The frozen model, split, features, thresholds, horizons and held-out families are
unchanged. Only the maximum streamed rows per scenario is reduced after the
source audit established that all three frozen clean onsets occur within the
first 615 benign flows of their scenarios.
"""
import v23_iot23_unseen_forecast as v23

v23.MAX_ROWS_PER_SCENARIO = 100_000

if __name__ == "__main__":
    v23.main()
