import os
import xattr
import plistlib
import argparse
import sys
import csv
import math
import string
import time
from collections import Counter

# ANSI escape codes
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"

MAX_EA_SIZE = 10 * 1024 * 1024 
SKEW_THRESHOLD_DAYS = 3 

def calculate_entropy(data):
    if not data: return 0
    entropy = 0
    data_len = len(data)
    counts = Counter(data)
    for count in counts.values():
        p = count / data_len
        entropy -= p * math.log2(p)
    return round(entropy, 2)

def sanitize_for_terminal(text):
    if not isinstance(text, str):
        text = str(text)
    return text.replace('\x1b', '[ESC]')

def sanitize_for_csv(text):
    text_str = str(text)
    if text_str and text_str[0] in ('=', '+', '-', '@'):
        return f"'{text_str}"
    return text_str

def decode_ea_content(raw_value):
    if raw_value.startswith(b'bplist00'):
        try:
            parsed = plistlib.loads(raw_value)
            return f"[BPLIST] {parsed}"
        except: pass
    try:
        return raw_value.decode('utf-8').strip()
    except UnicodeDecodeError:
        return f"HEX:{raw_value.hex()}"

def process_file(path, results, calc_entropy=False, check_skew=False):
    if os.path.islink(path):
        return False, False, False
        
    found_any = False
    high_entropy_found = False
    is_skewed = False
    readable_mtime = "N/A"
    
    try:
        # Only perform disk I/O for timestamps if requested
        if check_skew:
            file_stat = os.stat(path)
            mtime = file_stat.st_mtime
            readable_mtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))
            current_time = time.time()
            if (current_time - mtime) < (SKEW_THRESHOLD_DAYS * 86400):
                is_skewed = True

        attrs = xattr.listxattr(path)
        if attrs:
            found_any = True
            for attr_name in attrs:
                raw_val = xattr.getxattr(path, attr_name)
                
                if len(raw_val) > MAX_EA_SIZE:
                    content_raw = f"[!] EA TOO LARGE ({len(raw_val)} bytes)"
                    entropy_score = "N/A"
                else:
                    content_raw = decode_ea_content(raw_val)
                    entropy_score = calculate_entropy(raw_val) if calc_entropy else "N/A"

                entry = {
                    'file_path': path,
                    'attribute_key': attr_name,
                    'content': content_raw,
                    'is_high_entropy': False,
                    'is_skewed': is_skewed
                }

                if check_skew:
                    entry['mtime'] = readable_mtime

                if calc_entropy and isinstance(entropy_score, (float, int)):
                    entry['entropy'] = entropy_score
                    if entropy_score > 7:
                        entry['is_high_entropy'] = True
                        high_entropy_found = True
                else:
                    entry['entropy'] = entropy_score
                
                results.append(entry)
    except (PermissionError, OSError):
        pass
    return found_any, high_entropy_found, is_skewed

def scan_logic(target, is_dir, output_file=None, calc_entropy=False, check_skew=False):
    results = []
    files_scanned = 0
    files_with_ea = 0
    files_with_high_entropy = 0
    skew_alerts = 0

    if is_dir:
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            for file in files:
                files_scanned += 1
                path = os.path.join(root, file)
                has_ea, has_hi_e, has_skew = process_file(path, results, calc_entropy, check_skew)
                if has_ea: files_with_ea += 1
                if has_hi_e: files_with_high_entropy += 1
                if has_skew and has_ea: skew_alerts += 1
    else:
        files_scanned = 1
        has_ea, has_hi_e, has_skew = process_file(target, results, calc_entropy, check_skew)
        if has_ea: files_with_ea = 1
        if has_hi_e: files_with_high_entropy = 1
        if has_skew and has_ea: skew_alerts = 1

    # Dynamic Column widths
    line_length = 110
    if calc_entropy: line_length += 20
    if check_skew: line_length += 25

    header = f"\n{'File Path':<40} | "
    if check_skew: header += f"{'Last Modified':<20} | "
    header += f"{'Key':<25}"
    if calc_entropy: header += f" | {'Entropy':<7}"
    header += " | Content"
    
    print(header)
    print("-" * line_length)

    for entry in results:
        display_content = sanitize_for_terminal(entry['content'])
        line = f"{entry['file_path']:<40} | "
        if check_skew: line += f"{entry['mtime']:<20} | "
        line += f"{entry['attribute_key']:<25}"
        if calc_entropy: line += f" | {entry['entropy']:<7}"
        line += f" | {display_content}"
        
        if entry.get('is_high_entropy'):
            print(f"{RED}{line}{RESET}")
        elif entry.get('is_skewed'):
            print(f"{YELLOW}{line}{RESET}")
        else:
            print(line)

    print("-" * line_length)
    summary = f"Summary: Scanned: {files_scanned} | w/ EA: {files_with_ea}"
    if calc_entropy: summary += f" | High Entropy (>7): {files_with_high_entropy}"
    if check_skew: summary += f" | Recent Skew Alerts: {skew_alerts}"
    print(summary)
    print("-" * line_length)

    if output_file and results:
        fieldnames = ['file_path', 'attribute_key', 'content']
        if check_skew: fieldnames.insert(1, 'mtime')
        if calc_entropy: fieldnames.insert(3 if check_skew else 2, 'entropy')
        
        with open(output_file, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for row in results:
                row['content'] = sanitize_for_csv(row['content'])
                writer.writerow(row)
        print(f"[+] Report exported to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="XTT: Extended Attribute Triage")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--directory", help="Recursive scan of a directory.")
    group.add_argument("-f", "--file", help="Scan a single file.")
    parser.add_argument("-e", "--entropy", action="store_true", help="Calculate entropy.")
    parser.add_argument("-t", "--time-skew", action="store_true", help="Flag files modified within last 72h.")
    parser.add_argument("-w", "--write", help="Export results to CSV.")
    
    if len(sys.argv) == 1:
        parser.print_help(); sys.exit(1)
        
    args = parser.parse_args()
    target = args.directory if args.directory else args.file
    
    if os.path.exists(target):
        scan_logic(target, True if args.directory else False, args.write, args.entropy, args.time_skew)
    else:
        print(f"Error: Path '{target}' not found."); sys.exit(1)

if __name__ == "__main__":
    main()
