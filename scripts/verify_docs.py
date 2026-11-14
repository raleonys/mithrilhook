#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check public version examples, local Markdown links and exact branding."""
import hashlib
import json
from pathlib import Path
import re
import struct
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def check_local_links(root, documents):
    links = 0
    for document in documents:
        text = document.read_text()
        targets = re.findall(r'!?\[[^\]\n]*\]\(([^)\n]+)\)', text)
        targets += re.findall(r'^\[[^\]\n]+\]:\s*(\S+)', text, re.M)
        targets += re.findall(r'\b(?:src|href)=["\']([^"\']+)["\']', text)
        for target in targets:
            target = target.strip()
            target = target[1:target.index('>')] if target.startswith('<') else target.split()[0]
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            path = unquote(parsed.path)
            local = root / path.lstrip('/') if path.startswith('/') else document.parent / path
            local = local.resolve()
            if not local.is_relative_to(root) or not local.exists():
                raise ValueError('Broken local documentation link: ' +
                                 str(document.relative_to(root)) + ' -> ' + target)
            links += 1
    return links


def verify():
    version = (ROOT / 'VERSION').read_text().strip()
    patterns = {
        'README.md': r'^\*\*Version: ' + re.escape(version) + r'\.\*\*',
        'CHANGELOG.md': r'^## \[' + re.escape(version) + r'\]',
        'docs/RELEASE.md': r'^# MithrilHook ' + re.escape(version) + r' stable release$',
        'docs/VALIDATION.md': r'^\*\*Distribution version: ' + re.escape(version) + r'\.\*\*',
        'docs/REMAINING_WORK.md': r'^\*\*Library version: ' + re.escape(version) + r'\.\*\*',
        'docs/BENCHMARKS.md': r'^## ' + re.escape(version) + r' release evidence$',
    }
    for name, pattern in patterns.items():
        text = (ROOT / name).read_text()
        if not re.search(pattern, text, re.M):
            raise ValueError('Stale public version: ' + name)
        if re.search(r'publication (?:remains |is )?paused|prepared distribution|prepared source version', text, re.I):
            raise ValueError('Stale publication status: ' + name)
    entries = re.findall(r'^## \[([^]]+)\]', (ROOT / 'CHANGELOG.md').read_text(), re.M)
    if not entries or entries[0] != version:
        raise ValueError('Current version is not the first changelog entry')
    requests = re.findall(r'find_package\(MithrilHook (\d+\.\d+\.\d+) EXACT',
                          (ROOT / 'tests/package/CMakeLists.txt').read_text())
    if not requests or set(requests) != {version}:
        raise ValueError('Stale installed-consumer version request')

    documents = [p for p in sorted(ROOT.rglob('*.md'))
                 if p.relative_to(ROOT).parts[0] not in {'.git', 'build', 'dist'}]
    links = check_local_links(ROOT, documents)
    branding = json.loads((ROOT / 'metadata/BRANDING.json').read_text())['logo']
    logo = (ROOT / branding['path']).read_bytes()
    if hashlib.sha256(logo).hexdigest() != branding['sha256']:
        raise ValueError('Approved branding hash mismatch')
    if logo[:8] != b'\x89PNG\r\n\x1a\n' or struct.unpack('>II', logo[16:24]) != (branding['width'], branding['height']):
        raise ValueError('Approved branding dimensions mismatch')
    print(f'PASS: {len(documents)} Markdown documents, {links} local links, '
          f'{version} public versions and exact approved branding')


if __name__ == '__main__':
    verify()
