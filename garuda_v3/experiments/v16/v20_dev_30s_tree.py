"""V20 development gate: 30-second unseen-family future forecasting.

This deliberately reuses the frozen V19 network-only tree architecture and only
changes temporal resolution. Final-validation families remain unscored.
"""
from pathlib import Path

import v19_dev_highres_tree as v19

v19.WINDOW_SECONDS = 30
v19.HISTORY_WINDOWS = 16   # 8 minutes
v19.FUTURE_WINDOWS = 8    # 4 minutes
v19.OUT = Path("artifacts/v20_dev")
v19.OUT.mkdir(parents=True, exist_ok=True)

if __name__ == "__main__":
    v19.main()
