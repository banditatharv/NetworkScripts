#!/usr/bin/env python3
"""
nuclei_to_xlsx.py
Convert Nuclei .md output files to a structured Excel report.

Usage:
    python nuclei_to_xlsx.py -i Nuclei-result/ -o nuclei-report-custom.xlsx
    python nuclei_to_xlsx.py --help
"""

import argparse
import os
import re
import sys
from pathlib import Path
from collections import defaultdict

try:
    import xlsxwriter
except ImportError:
    print("❌ Missing dependency: xlsxwriter", file=sys.stderr)
    print("💡 Install with: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)


# ─────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────

def extract_template_prefixes(filenames):
    """
    Build a set of unique template prefixes using the logic:
    split filename by '-', take first 1-2 parts, join with '-'.
    Returns a sorted list (longest first) for greedy matching.
    """
    prefixes = set()
    for fname in filenames:
        if not fname.endswith('.md'):
            continue
        name = fname[:-3]  # remove .md
        parts = name.split('-')
        # Try 2-part first, fallback to 1-part
        if len(parts) >= 2:
            prefixes.add('-'.join(parts[:2]))
        else:
            prefixes.add(parts[0])
    # Sort by length descending for longest-match-first
    return sorted(prefixes, key=len, reverse=True)


def match_template_prefix(filename, prefixes):
    """
    Match the longest template prefix from the list against the filename.
    Returns the matched prefix or None.
    """
    name = Path(filename).stem  # remove .md
    for prefix in prefixes:
        if name.startswith(prefix + '-'):
            return prefix
    return None


def extract_domain(filename, template_prefix):
    """
    Extract domain from filename by:
    1. Removing .md extension
    2. Removing matched template prefix + trailing '-'
    3. Removing UUID pattern at the end
    4. Stripping any remaining leading/trailing '-'
    """
    name = Path(filename).stem
    # Remove template prefix
    if name.startswith(template_prefix + '-'):
        remainder = name[len(template_prefix) + 1:]
    else:
        remainder = name
    
    # Remove UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    uuid_pattern = r'-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
    domain = re.sub(uuid_pattern, '', remainder, flags=re.IGNORECASE)
    
    # Clean up any stray dashes
    return domain.strip('-')


def parse_metadata_table(content):
    """
    Parse the markdown table with Key | Value pairs.
    Returns a dict of metadata fields.
    """
    metadata = {}
    lines = content.split('\n')
    in_table = False
    
    for line in lines:
        # Detect start of metadata table
        if '| Key | Value |' in line:
            in_table = True
            continue
        if in_table:
            # Stop at end of table (empty line or new section)
            if line.strip() == '' or line.strip().startswith('**'):
                break
            # Parse table row: | Name | Apache Detection |
            match = re.match(r'\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|', line)
            if match:
                key = match.group(1).strip()
                value = match.group(2).strip()
                # Strip HTML tags from description
                if key == 'Description':
                    value = re.sub(r'<[^>]+>', '', value)
                metadata[key] = value
    return metadata


def extract_curl_command(content):
    """
    Extract the curl command from the **CURL command** code block.
    Returns the command string or 'N/A' if not found.
    """
    # Look for the CURL command section
    curl_marker = '**CURL command**'
    if curl_marker not in content:
        return 'N/A'
    
    # Find the marker and get content after it
    idx = content.find(curl_marker)
    after = content[idx + len(curl_marker):]
    
    # Look for ```sh block
    sh_block = re.search(r'```sh\s*\n(.*?)```', after, re.DOTALL)
    if sh_block:
        return sh_block.group(1).strip()
    
    # Fallback: look for any ``` block
    any_block = re.search(r'```\s*\n(.*?)```', after, re.DOTALL)
    if any_block:
        return any_block.group(1).strip()
    
    return 'N/A'


def parse_nuclei_file(filepath, template_prefixes):
    """
    Parse a single Nuclei .md file and return a dict of extracted data.
    """
    filename = os.path.basename(filepath)
    
    # Match template prefix
    template = match_template_prefix(filename, template_prefixes)
    if not template:
        # Fallback: use first 2 parts as template
        parts = Path(filename).stem.split('-')
        template = '-'.join(parts[:2]) if len(parts) >= 2 else parts[0]
        print(f"⚠️  No prefix match for {filename}, using fallback: {template}", file=sys.stderr)
    
    # Extract domain
    domain = extract_domain(filename, template)
    
    # Read file content
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"❌ Error reading {filepath}: {e}", file=sys.stderr)
        return None
    
    # Parse metadata
    metadata = parse_metadata_table(content)
    
    # Extract curl command
    curl_cmd = extract_curl_command(content)
    
    # Build result row
    return {
        'template_name': template,
        'target_domain': domain,
        'severity': metadata.get('Severity', 'N/A'),
        'description': metadata.get('Description', 'N/A'),
        'tags': metadata.get('Tags', 'N/A'),
        'cvss_score': metadata.get('CVSS-Score', 'N/A'),
        'cwe_id': metadata.get('CWE-ID', 'N/A'),
        'curl_command': curl_cmd,
        'source_file': filename
    }


def write_xlsx(rows, output_path):
    """
    Write parsed rows to an Excel file with formatting:
    - Merged cells for consecutive same template_name
    - Frozen headers, filters, auto-column width, text wrap
    """
    workbook = xlsxwriter.Workbook(output_path)
    worksheet = workbook.add_worksheet('Nuclei Findings')
    
    # Formats
    header_fmt = workbook.add_format({'bold': True, 'bg_color': '#4472C4', 'font_color': 'white', 'border': 1})
    cell_fmt = workbook.add_format({'border': 1, 'text_wrap': True})
    merge_fmt = workbook.add_format({'border': 1, 'align': 'center', 'valign': 'vcenter', 'text_wrap': True})
    
    # Headers
    headers = [
        'Template_Name', 'Target_Domain', 'Severity', 'Description',
        'Tags', 'CVSS_Score', 'CWE_ID', 'Curl_Command', 'Source_File'
    ]
    worksheet.write_row(0, 0, headers, header_fmt)
    
    # Sort rows by template_name then domain for clean merging
    rows_sorted = sorted(rows, key=lambda x: (x['template_name'], x['target_domain']))
    
    # Write data rows
    row_idx = 1
    current_template = None
    merge_start_row = None
    
    for row_data in rows_sorted:
        # Handle template name merging
        if row_data['template_name'] != current_template:
            # Close previous merge if exists
            if merge_start_row is not None and merge_start_row < row_idx - 1:
                worksheet.merge_range(merge_start_row, 0, row_idx - 1, 0, 
                                    rows_sorted[merge_start_row]['template_name'], merge_fmt)
            # Start new merge
            merge_start_row = row_idx
            current_template = row_data['template_name']
        
        # Write row (template column written separately for merging)
        worksheet.write(row_idx, 1, row_data['target_domain'], cell_fmt)
        worksheet.write(row_idx, 2, row_data['severity'], cell_fmt)
        worksheet.write(row_idx, 3, row_data['description'], cell_fmt)
        worksheet.write(row_idx, 4, row_data['tags'], cell_fmt)
        worksheet.write(row_idx, 5, row_data['cvss_score'], cell_fmt)
        worksheet.write(row_idx, 6, row_data['cwe_id'], cell_fmt)
        worksheet.write(row_idx, 7, row_data['curl_command'], cell_fmt)
        worksheet.write(row_idx, 8, row_data['source_file'], cell_fmt)
        
        row_idx += 1
    
    # Close final merge
    if merge_start_row is not None and merge_start_row < row_idx - 1:
        worksheet.merge_range(merge_start_row, 0, row_idx - 1, 0, 
                            rows_sorted[merge_start_row]['template_name'], merge_fmt)
    
    # Formatting: auto-width, freeze panes, filter
    worksheet.set_column(0, 0, 20)  # Template_Name
    worksheet.set_column(1, 1, 30)  # Target_Domain
    worksheet.set_column(2, 2, 12)  # Severity
    worksheet.set_column(3, 3, 50)  # Description (wide + wrap)
    worksheet.set_column(4, 4, 25)  # Tags
    worksheet.set_column(5, 5, 12)  # CVSS_Score
    worksheet.set_column(6, 6, 15)  # CWE_ID
    worksheet.set_column(7, 7, 60)  # Curl_Command (wide + wrap)
    worksheet.set_column(8, 8, 40)  # Source_File
    
    worksheet.freeze_panes(1, 0)  # Freeze header row
    worksheet.autofilter(0, 0, row_idx - 1, len(headers) - 1)  # Add filter to headers
    
    workbook.close()
    print(f"✅ Report saved to: {output_path}")


# ─────────────────────────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Convert Nuclei .md output files to a structured Excel report.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -i Nuclei-result/ -o nuclei-report-custom.xlsx
  %(prog)s --input-dir . --severity high,critical
  %(prog)s  # Uses current dir, outputs nuclei-report.xlsx

Output columns:
  Template_Name | Target_Domain | Severity | Description | Tags | CVSS_Score | CWE_ID | Curl_Command | Source_File
        '''
    )
    
    parser.add_argument('-i', '--input-dir', default='.',
                        help='Directory containing Nuclei .md files (default: current directory)')
    parser.add_argument('-o', '--output', default='nuclei-report.xlsx',
                        help='Output Excel filename (default: nuclei-report.xlsx)')
    parser.add_argument('--severity', type=str,
                        help='Optional: comma-separated list of severities to include (e.g., high,critical)')
    
    args = parser.parse_args()
    
    # Validate input directory
    input_path = Path(args.input_dir)
    if not input_path.is_dir():
        print(f"❌ Input directory not found: {args.input_dir}", file=sys.stderr)
        sys.exit(1)
    
    # Find all .md files
    md_files = list(input_path.glob('*.md'))
    if not md_files:
        print(f"⚠️  No .md files found in {args.input_dir}", file=sys.stderr)
        sys.exit(0)
    
    print(f"🔍 Found {len(md_files)} .md files in {args.input_dir}")
    
    # Step 1: Extract template prefixes from all filenames
    filenames = [f.name for f in md_files]
    template_prefixes = extract_template_prefixes(filenames)
    print(f"📋 Identified {len(template_prefixes)} unique template prefixes")
    
    # Step 2: Parse each file
    rows = []
    for md_file in md_files:
        result = parse_nuclei_file(str(md_file), template_prefixes)
        if result:
            # Apply severity filter if specified
            if args.severity:
                allowed = [s.strip().lower() for s in args.severity.split(',')]
                if result['severity'].lower() not in allowed:
                    continue
            rows.append(result)
    
    if not rows:
        print("⚠️  No valid findings to export", file=sys.stderr)
        sys.exit(0)
    
    print(f"📊 Processed {len(rows)} findings")
    
    # Step 3: Write to XLSX
    write_xlsx(rows, args.output)


if __name__ == '__main__':
    main()