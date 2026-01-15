# XTT - Extended Attribute Triage

A forensic utility for the identification, extraction, and decoding of Extended Attributes (EAs) on Linux and macOS.

## Features
- **Mutually Exclusive Targets:** Choose between single file (`-f`) or recursive directory (`-d`) scans.
- **No Truncation:** Displays the full content of all attributes.
- **macOS Plist Support:** Built-in support for macOS Binary Plists (e.g., `WhereFroms`, `Quarantine`).
- **CSV Reporting:** Export findings using the `-w` flag.

## Usage
### See available options
`python3 xtt.py -h`


### Scan a folder recursively
`python3 xtt.py -d teste_dir/`

<img width="1202" height="354" alt="image" src="https://github.com/user-attachments/assets/77fff018-b68c-4ce4-9daa-b2e33c880c65" />

### Analyze a single suspect binary
`python3 xtt.py -f test.txt`

<img width="1201" height="270" alt="image" src="https://github.com/user-attachments/assets/289aaee2-f847-4864-bda7-6d6c901058cc" />

### Generate a forensic report
`python3 xtt.py -d test_dir/ -w report.csv`

<img width="1189" height="398" alt="image" src="https://github.com/user-attachments/assets/903c86e6-5b76-4d33-86b3-ca3a6173640a" />

