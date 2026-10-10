#!/usr/bin/env python3
"""Static, read-only FiveM backdoor scanner. Python 3.9+, standard library only."""
import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

EXTENSIONS = {'.js', '.cjs', '.mjs', '.lua', '.ts', '.cfg'}
MAX_SIZE = 12 * 1024 * 1024
KNOWN_DOMAIN = re.compile(r'(?i)\bz1lly\.org\b')
KNOWN_ENDPOINT = re.compile(r'\bbekJJ(?:gg|cfxre)?\b')
KNOWN_MARKERS = re.compile(r'\b(?:kmlkznbgfs|pmloxbulec|kmloxbukpm|dmloxbuarh|pmlkznbgyz|dmlkznbgois)\b')
REMOTE_EVAL = re.compile(r'\beval\s*\(\s*(?:data\w*|response\w*|body\w*|payload\w*|d)\b', re.I)
NETWORK = re.compile(r'\brequire\s*\(\s*[\'\"]https?[\'\"]\s*\)|\bhttps?\.get\s*\(|\bfetch\s*\(', re.I)
EVAL = re.compile(r'\beval\s*\(|\bnew\s+Function\s*\(', re.I)
XOR = re.compile(r'fromCharCode\s*\([^\n]{0,120}\^|charCodeAt\s*\([^\n]{0,80}\^', re.I)
ARRAY = re.compile(r'\b(?:const|let|var)\s+(\w+)\s*=\s*\[([\d,\s]{50,})\]\s*;', re.S)
KEY = re.compile(r'\b(?:const|let|var)\s+(\w+)\s*=\s*(\d{1,3})\s*;')
UNICODE = re.compile(r'\\u([0-9a-fA-F]{4})')
URL = re.compile(r'https?://[^\s\'\"`<>\\]{3,180}', re.I)


def decode_layers(source):
    """Decode bounded XOR numeric arrays and escaped Unicode; never execute source."""
    layers = []
    keys = [(m.group(1), int(m.group(2))) for m in KEY.finditer(source) if int(m.group(2)) <= 255][:24]
    for match in list(ARRAY.finditer(source))[:24]:
        nums = [int(x) for x in re.findall(r'\d+', match.group(2))]
        if not 25 <= len(nums) <= 150000 or any(n > 65535 for n in nums):
            continue
        for name, key in keys:
            decoded = ''.join(chr(n ^ key) for n in nums)
            sample = decoded[:2000]
            if sum(c.isprintable() or c in '\r\n\t' for c in sample) / len(sample) < .90:
                continue
            if any(x in decoded for x in ('eval(', 'require(', 'https://', 'function ', 'const ')):
                layers.append((f'xor_array:{match.group(1)}:key={key}({name})', decoded))
    # Decode the unicode-escape-plus-XOR variant without applying XOR to unrelated code.
    for match in list(re.finditer(r'(?:\\u[0-9a-fA-F]{4}){20,}', source))[:16]:
        chars = [int(x, 16) for x in UNICODE.findall(match.group())]
        plain = ''.join(chr(c) for c in chars)
        layers.append(('unicode_escape', plain))
        for key in range(256):
            decoded = ''.join(chr(c ^ key) for c in chars)
            if KNOWN_DOMAIN.search(decoded) or (REMOTE_EVAL.search(decoded) and NETWORK.search(decoded)):
                layers.append((f'unicode_xor:key={key}', decoded))
    return layers


def classify(layers):
    indicators = set()
    evidence = []
    urls = set()
    for layer, content in layers:
        checks = {
            'known_loader_domain': KNOWN_DOMAIN,
            'known_loader_endpoint': KNOWN_ENDPOINT,
            'known_loader_marker': KNOWN_MARKERS,
            'remote_eval': REMOTE_EVAL,
            'network_client': NETWORK,
            'dynamic_eval': EVAL,
            'xor_decoder': XOR,
        }
        for label, regex in checks.items():
            if regex.search(content):
                indicators.add(label)
                evidence.append({'layer': layer, 'indicator': label})
        urls.update(URL.findall(content))
    if 'known_loader_domain' in indicators or ('known_loader_endpoint' in indicators and 'remote_eval' in indicators):
        risk = 'CRITICAL'
    elif 'known_loader_marker' in indicators:
        risk = 'HIGH'  # a marker alone does not prove execution
    elif 'remote_eval' in indicators and 'network_client' in indicators:
        risk = 'HIGH'
    elif 'remote_eval' in indicators or ('xor_decoder' in indicators and 'dynamic_eval' in indicators):
        risk = 'REVIEW'
    else:
        risk = 'NONE'
    return risk, evidence, sorted(urls)[:15]


def inspect_file(path, root, max_size=MAX_SIZE):
    stat = path.stat(follow_symlinks=False)
    if stat.st_size > max_size:
        return None, 'oversize'
    raw = path.read_bytes()
    source = raw.decode('utf-8', 'replace')
    layers = [('original', source)] + decode_layers(source)
    risk, evidence, urls = classify(layers)
    if risk == 'NONE':
        return None, None
    return {'file': str(path), 'relative_path': str(path.relative_to(root)),
            'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
            'risk': risk, 'indicators': evidence, 'urls': urls,
            'decoded_layers': [name for name, _ in layers[1:]]}, None


def scan_tree(root, max_size=MAX_SIZE):
    findings, errors, counts = [], [], Counter()
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if not (Path(directory) / d).is_symlink()]
        for filename in files:
            path = Path(directory) / filename
            if path.suffix.lower() not in EXTENSIONS or path.is_symlink():
                continue
            counts['examined'] += 1
            try:
                result, skipped = inspect_file(path, root, max_size)
                if skipped:
                    counts['skipped_oversize'] += 1
                elif result:
                    findings.append(result)
                    counts[result['risk']] += 1
            except (OSError, ValueError) as exc:
                errors.append({'file': str(path), 'error': str(exc)})
    order = {'CRITICAL': 0, 'HIGH': 1, 'REVIEW': 2}
    findings.sort(key=lambda x: (order[x['risk']], x['relative_path']))
    return findings, errors, dict(counts)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path, help='FiveM txData or resources directory')
    parser.add_argument('--json', type=Path, help='Write report JSON (outside scan root)')
    parser.add_argument('--max-mb', type=int, default=12, help='Maximum file size in MiB (default: 12)')
    parser.add_argument('--show-review', action='store_true', help='Print REVIEW findings too')
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        parser.error('Scan root is not a directory')
    if args.max_mb < 1 or args.max_mb > 128:
        parser.error('--max-mb must be 1..128')
    if args.json:
        output = args.json.resolve()
        if output == root or root in output.parents:
            parser.error('JSON output must be outside the scanned directory')
    findings, errors, counts = scan_tree(root, args.max_mb * 1024 * 1024)
    report = {'schema_version': 1, 'generated_utc': datetime.now(timezone.utc).isoformat(),
              'root': str(root), 'counts': counts, 'matches': findings, 'errors': errors}
    print(f"Examined: {counts.get('examined', 0)} | CRITICAL: {counts.get('CRITICAL', 0)} | "
          f"HIGH: {counts.get('HIGH', 0)} | REVIEW: {counts.get('REVIEW', 0)} | "
          f"Skipped (size): {counts.get('skipped_oversize', 0)} | Errors: {len(errors)}")
    for item in findings:
        if item['risk'] == 'REVIEW' and not args.show_review:
            continue
        print(f"[{item['risk']}] {item['relative_path']}")
        print('  ' + ', '.join(sorted({x['indicator'] for x in item['indicators']})))
    if args.json:
        args.json.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(f'Report: {args.json}')
    return 2 if counts.get('CRITICAL', 0) else 1 if counts.get('HIGH', 0) else 0


if __name__ == '__main__':
    sys.exit(main())
