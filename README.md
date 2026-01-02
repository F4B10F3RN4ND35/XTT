# XTA - Extended Attribute Auditor

A forensic utility to extract and decode Extended Attributes on Linux and macOS.

## Features
- **Mutually Exclusive Targets:** Choose between single file (`-f`) or recursive directory (`-d`) scans.
- **No Truncation:** Displays the full content of all attributes.
- **macOS Plist Support:** Automatically decodes binary property lists.
- **CSV Reporting:** Export findings using the `-w` flag.

## Usage
### Scan a folder recursively
`python3 xta.py -d ./Downloads`

### Analyze a single suspect binary
`python3 xta.py -f ./malicious_file.bin`

### Generate a forensic report
`python3 xta.py -d / -w full_system_ea_report.csv`

## Requirements
- Python 3.x
- `xattr` library (`pip install xattr`)
