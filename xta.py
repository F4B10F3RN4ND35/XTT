import os
import xattr
import plistlib
import argparse
import sys
import csv

def decode_ea_content(raw_value):
    """
    Decodes attribute content based on data headers.
    """
    if raw_value.startswith(b'bplist00'):
        try:
            parsed = plistlib.loads(raw_value)
            return f"[BPLIST] {parsed}"
        except Exception:
            pass

    try:
        return raw_value.decode('utf-8').strip()
    except UnicodeDecodeError:
        return f"HEX:{raw_value.hex()}"

def scan_ea(directory, output_file=None):
    """
    Recursively audits a directory and optionally writes to CSV.
    """
    files_scanned = 0
    files_with_ea = 0
    total_ea_found = 0
    results = []

    for root, _, files in os.walk(directory):
        for file in files:
            files_scanned += 1
            path = os.path.join(root, file)
            try:
                attrs = xattr.listxattr(path)
                if attrs:
                    files_with_ea += 1
                    for attr_name in attrs:
                        total_ea_found += 1
                        raw_val = xattr.getxattr(path, attr_name)
                        decoded_val = decode_ea_content(raw_val)
                        results.append({
                            'file_path': path,
                            'attribute_key': attr_name,
                            'content': decoded_val
                        })
            except (PermissionError, OSError):
                continue

    # Display to Terminal
    header = f"{'File Path':<45} | {'Attribute Key':<35} | {'Content'}"
    print(header)
    print("-" * len(header))
    for entry in results:
        display_path = (entry['file_path'][:42] + '..') if len(entry['file_path']) > 44 else entry['file_path']
        print(f"{display_path:<45} | {entry['attribute_key']:<35} | {entry['content'][:50]}...")

    print("-" * len(header))
    print(f"Summary: Scanned {files_scanned} | Files w/ EA: {files_with_ea} | Total EA: {total_ea_found}")

    # Export to CSV if -w is provided
    if output_file:
        try:
            with open(output_file, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['file_path', 'attribute_key', 'content'])
                writer.writeheader()
                writer.writerows(results)
            print(f"\n[+] Results successfully exported to: {output_file}")
        except Exception as e:
            print(f"\n[!] Failed to write CSV: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="DFIR Tool: Identify and Extract Extended Attributes (Linux/macOS).",
        epilog="Strategic Tip: Use CSV export for large-scale timeline analysis."
    )
    parser.add_argument("path", help="The target directory or mount point to scan.")
    parser.add_argument("-w", "--write", help="Export results to a CSV file (e.g., -w report.csv)")
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()

    if os.path.isdir(args.path):
        scan_ea(args.path, args.write)
    else:
        print(f"Error: {args.path} is not a valid directory.")
        sys.exit(1)

if __name__ == "__main__":
    main()