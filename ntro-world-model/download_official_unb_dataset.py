"""
NTRO SIH26153: Official Canadian Institute for Cybersecurity (UNB) Dataset Downloader
Directly streams and downloads the authentic published CSE-CIC-IDS2018 dataset from the
official UNB AWS S3 Open Data Repository:
https://cse-cic-ids2018.s3.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv
"""

import urllib.request
import os
import sys
import time

OFFICIAL_UNB_AWS_URL = "https://cse-cic-ids2018.s3.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv"

def download_official_dataset(target_path, max_rows=150000):
    print("=" * 85)
    print("🌐 DOWNLOADING OFFICIAL PUBLISHED UNB CSE-CIC-IDS2018 DATASET FROM AWS S3")
    print(f"   Source URL: {OFFICIAL_UNB_AWS_URL}")
    print(f"   Destination: {target_path}")
    print("=" * 85)

    os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
    req = urllib.request.Request(
        OFFICIAL_UNB_AWS_URL,
        headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"}
    )

    start_time = time.time()
    downloaded_rows = 0

    with urllib.request.urlopen(req, timeout=45) as resp, open(target_path, "w", encoding="utf-8") as fout:
        buffer = ""
        while True:
            chunk = resp.read(1024 * 1024 * 4) # 4MB network buffer
            if not chunk:
                break
            buffer += chunk.decode("utf-8", errors="ignore")
            lines = buffer.split("\n")
            buffer = lines[-1]

            for line in lines[:-1]:
                if line.strip():
                    fout.write(line + "\n")
                    downloaded_rows += 1
                    if downloaded_rows >= max_rows:
                        break
            if downloaded_rows >= max_rows:
                break
            print(f"  📥 Streaming genuine UNB packets: {downloaded_rows:,} / {max_rows:,} rows...", end="\r")

    elapsed = time.time() - start_time
    size_mb = os.path.getsize(target_path) / (1024 * 1024)
    print(f"\n\n✅ OFFICIAL UNB DATASET SUCCESSFULLY DOWNLOADED!")
    print(f"   Total Genuine Rows: {downloaded_rows:,}")
    print(f"   Total File Size: {size_mb:.2f} MB")
    print(f"   Download Time: {elapsed:.2f} seconds")
    print("=" * 85 + "\n")

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    target = os.path.join(script_dir, "cicids2018_data", "Friday-02-03-2018_Infiltration_REAL.csv")
    download_official_dataset(target, max_rows=150000)
