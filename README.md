# XTT - Extended Attributes Triage

A forensic utility for the identification, extraction, and decoding of Extended Attributes (EAs) on Linux and macOS.

## Features
- **Mutually Exclusive Targets:** Choose between single file (`-f`) or recursive directory (`-d`) scans.
- **No Truncation:** Displays the full content of all attributes.
- **macOS Plist Support:** Built-in support for macOS Binary Plists (e.g., `WhereFroms`, `Quarantine`).
- **CSV Reporting:** Export findings using the `-w` flag.

## Usage
### See available options
`python3 xtt.py -h`

<img width="750" height="204" alt="image" src="https://github.com/user-attachments/assets/2e103449-eaec-42d1-af7c-3db7c4630d0d" />

### Scan a folder recursively
`python3 xtt.py -d test_dir/`

<img width="1202" height="354" alt="image" src="https://github.com/user-attachments/assets/77fff018-b68c-4ce4-9daa-b2e33c880c65" />

### Analyze a single file
`python3 xtt.py -f test.txt`

<img width="1201" height="270" alt="image" src="https://github.com/user-attachments/assets/289aaee2-f847-4864-bda7-6d6c901058cc" />

### Generate a report
`python3 xtt.py -d test_dir/ -w report.csv`

<img width="1189" height="398" alt="image" src="https://github.com/user-attachments/assets/903c86e6-5b76-4d33-86b3-ca3a6173640a" />

