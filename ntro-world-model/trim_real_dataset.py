"""
NTRO SIH26153: Real Dataset Trimming & Normalization Utility
Trims large multi-gigabyte CSE-CIC-IDS2018 CSV dumps (e.g. from UNB or Kaggle)
to a focused, high-density 150,000-row subset covering the Infiltration attack window.
"""

import csv
import os
import sys

def trim_dataset(input_file, output_file, max_rows=150000):
    if not os.path.exists(input_file):
        print(f"⚠️ Input file '{input_file}' not found.")
        return False

    print(f"📂 Trimming '{input_file}' to max {max_rows:,} rows...")
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as fin, \
         open(output_file, 'w', newline='', encoding='utf-8') as fout:
        reader = csv.reader(fin)
        writer = csv.writer(fout)
        header = next(reader)
        writer.writerow(header)

        count = 0
        for row in reader:
            writer.writerow(row)
            count += 1
            if count >= max_rows:
                break

    file_size_mb = os.path.getsize(output_file) / (1024 * 1024)
    print(f"✅ Successfully created '{output_file}': {count:,} rows | {file_size_mb:.2f} MB")
    return True

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    in_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(script_dir, "cicids2018_data", "Friday-02-03-2018_Infiltration.csv")
    out_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(script_dir, "cicids2018_data", "Friday-02-03-2018_Infiltration_REAL.csv")
    trim_dataset(in_path, out_path, max_rows=150000)
