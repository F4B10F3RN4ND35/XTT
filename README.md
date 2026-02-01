# XTT - Extended Attributes Triage

A forensic utility for the identification, extraction, and decoding of Extended Attributes (EAs) on Linux and macOS.

## Features
- **Mutually Exclusive Targets:** Choose between single file (`-f`) or recursive directory (`-d`) scans.
- **No Truncation:** Displays the full content of all attributes.
- **macOS Plist Support:** Built-in support for macOS Binary Plists (e.g., `WhereFroms`, `Quarantine`).
- **CSV Reporting:** Export findings to CSV format.
- **Entropy Analysis (NEW):** Calculates entropy for every attribute to detect encrypted or packed payloads. Attributes with entropy higher than **7.0** (indicating encryption or packing) are automatically highlighted in **RED**.
- **Time Discrepancy Analysis (NEW)** Compares the file's Modification Time (`mtime`) against current system boundaries. Files modified within a **72-hour window** are highlighted in **YELLOW**.

## Usage
### See available options
`python3 xtt.py -h`

<img width="788" height="205" alt="Screenshot 2026-02-01 at 16 07 47" src="https://github.com/user-attachments/assets/42bd03d9-5490-456b-b79c-975861088148" />


### Scan a folder recursively
`python3 xtt.py -d test_dir/`

<img width="1202" height="354" alt="image" src="https://github.com/user-attachments/assets/77fff018-b68c-4ce4-9daa-b2e33c880c65" />

### Analyze a single file
`python3 xtt.py -f test.txt`

<img width="1201" height="270" alt="image" src="https://github.com/user-attachments/assets/289aaee2-f847-4864-bda7-6d6c901058cc" />

### Generate a report
`python3 xtt.py -d test_dir/ -w report.csv`

<img width="1189" height="398" alt="image" src="https://github.com/user-attachments/assets/903c86e6-5b76-4d33-86b3-ca3a6173640a" />

### Entropy analysis (NEW)
`python3 xtt.py -e -d test_dir/`
<img width="971" height="338" alt="mac_entropy" src="https://github.com/user-attachments/assets/10ecdcd5-5a27-4193-ac17-1ce31b76d0c0" />

### Time modification analysis (NEW)
`python3 xtt.py -t -d test_dir/`
<img width="971" height="338" alt="mac_time" src="https://github.com/user-attachments/assets/062290d0-3b7a-4d00-9358-a14148e514dd" />


## Entropy Score,Interpretation,Forensic Action

0.0 - 3.0 (Highly structured / Empty,Likely padding or null bytes.)

3.0 - 6.0 (Standard Text / Code,Likely legitimate configuration or scripts)

6.0 - 7.5 (Packed / Obfuscated,Suspicious. Possible packed malware or Base64 blobs)

7.5 - 8.0 (Encrypted / Compressed,CRITICAL. High probability of hidden payloads or encrypted C2 config)


