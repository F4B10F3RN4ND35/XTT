import os
import xattr
import plistlib
import argparse
import sys
import csv
import math
from collections import Counter

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    data_len = len(data)
    counts = Counter(data)
    for count in counts.values():
        p = count / data_len
        entropy -= p * math.log2(p)
    return round(entropy, 2)

def decode_ea_content(raw_value):
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

def process_file(path, results):
    found_any = False
    try:
        attrs = xattr.listxattr(path)
        if attrs:
            found_any = True
            for attr_name in attrs:
                raw_val = xattr.getxattr(path, attr_name)
                entropy_score = calculate_entropy(raw_val)
                decoded_val = decode_ea_content(raw_val)
                results.append({
                    'file_path': path,
                    'attribute_key': attr_name,
                    'entropy': entropy_score,
                    'content': decoded_val
                })
    except (PermissionError, OSError):
        pass
    return found_any

def scan_logic(target, is_dir, output_file=None):
    results = []
    files_scanned = 0
    files_with_ea = 0

    if is_dir:
        for root, _, files in os.walk(target):
            for file in files:
                files_scanned += 1
                path = os.path.join(root, file)
                if process_file(path, results):
                    files_with_ea += 1
    else:
        files_scanned = 1
        if process_file(target, results):
            files_with_ea = 1

    print(f"\n{'File Path':<40} | {'Key':<25} | {'Entropy':<7} | {'Content'}")
    print("-" * 130)
    for entry in results:
        print(f"{entry['file_path']:<40} | {entry['attribute_key']:<25} | {entry['entropy']:<7} | {entry['content']}")

    print("-" * 130)
    print(f"Summary: Scanned: {files_scanned} | With EA: {files_with_ea} | Total EAs: {len(results)}")

    if output_file and results:
        with open(output_file, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['file_path', 'attribute_key', 'entropy', 'content'])
            writer.writeheader()
            writer.writerows(results)
        print(f"[+] Report exported to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="XTT: Extended Attribute Triage (macOS/Linux) with Entropy Analysis.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--directory", help="Recursive scan of a directory.")
    group.add_argument("-f", "--file", help="Scan a single file.")
    parser.add_argument("-w", "--write", help="Export results to CSV.")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()
    target = args.directory if args.directory else args.file
    if os.path.exists(target):
        scan_logic(target, True if args.directory else False, args.write)

if __name__ == "__main__":
    main()












































































































    #Dedicado a Pietro e Matteo!!
