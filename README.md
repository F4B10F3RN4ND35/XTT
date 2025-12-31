# XTA - Extended Attribute Auditor

A DFIR tool for Linux and macOS to identify, extract, and decode Extended Attributes (EAs).

## Features
* **Cross-Platform:** Supports Linux and macOS.
* **Content Extraction:** Decodes macOS Binary Plists (WhereFroms, Quarantine).
* **Forensic Metrics:** Provides counts of scanned files vs. files with attributes.
* **CSV Export:** Use `-w` to generate reports for timeline analysis.

## Installation
```bash
pip install xattr

## Usage
python3 xta.py /path/to/scan -w report.csv
