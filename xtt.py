import os
import xattr
import plistlib
import argparse
import sys
import csv

def decode_ea_content(raw_value):
    """
    Decodes attribute content based on data headers.
    Ensures full content is returned without truncation.
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

def process_file(path, results):
    """Audits a single file for Extended Attributes."""
    found_any = False
    try:
        attrs = xattr.listxattr(path)
        if attrs:
            found_any = True
            for attr_name in attrs:
                raw_val = xattr.getxattr(path, attr_name)
                decoded_val = decode_ea_content(raw_val)
                results.append({
                    'file_path': path,
                    'attribute_key': attr_name,
                    'content': decoded_val
                })
    except (PermissionError, OSError):
       
        pass
    return found_any

def scan_logic(target, is_dir, output_file=None):
    """Manages the scanning process and reporting."""
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

   
    print(f"\n{'File Path':<50} | {'Attribute Key':<35} | {'Content'}")
    print("-" * 150)
    
    for entry in results:
      
        print(f"{entry['file_path']:<50} | {entry['attribute_key']:<35} | {entry['content']}")

    print("-" * 150)
    print(f"Summary:")
    print(f"  Total files scanned: {files_scanned}")
    print(f"  Files with Extended Attributes: {files_with_ea}")
    print(f"  Total attributes extracted: {len(results)}")

  
    if output_file and results:
        try:
            with open(output_file, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['file_path', 'attribute_key', 'content'])
                writer.writeheader()
                writer.writerows(results)
            print(f"\n[+] Full report exported to: {output_file}")
        except Exception as e:
            print(f"\n[!] Error writing CSV: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="XTA: Extended Attribute Auditor for DFIR (Linux & macOS).",
        epilog="Note: Use -d for recursive folder scans or -f for specific file analysis."
    )
    
   
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--directory", help="Recursive scan of a directory.")
    group.add_argument("-f", "--file", help="Scan a single specific file.")
    
    parser.add_argument("-w", "--write", help="Export full results to a CSV file.")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    
    target = args.directory if args.directory else args.file
    is_dir = True if args.directory else False

    if os.path.exists(target):
        scan_logic(target, is_dir, args.write)
    else:
        print(f"Error: Target path '{target}' does not exist.")
        sys.exit(1)

if __name__ == "__main__":
    main()