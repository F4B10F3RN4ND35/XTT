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
`python3 xtt.py -d ./Downloads`

### Analyze a single suspect binary
`python3 xtt.py -f ./malicious_file.bin`

### Generate a forensic report
`python3 xtt.py -d / -w report.csv`
