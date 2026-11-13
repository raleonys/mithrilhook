#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Verify the offline source inventory and the independent MithrilHook identity."""
import argparse
import hashlib
import json
from pathlib import Path
import re
ROOT=Path(__file__).resolve().parents[1]
MANIFEST='metadata/SOURCE_MANIFEST.json'
def members():
 result={}
 for path in sorted(ROOT.rglob('*')):
  relative=path.relative_to(ROOT)
  if relative.parts[0] in {'.git','build','dist'} or '__pycache__' in relative.parts:continue
  if path.is_symlink():raise ValueError('Unexpected source symlink: '+str(relative))
  if path.is_file() and relative.as_posix()!=MANIFEST:
   result[relative.as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
 return result
def verify():
 expected=json.loads((ROOT/MANIFEST).read_text())['files'];actual=members()
 changes=[name for name in sorted(expected.keys()|actual.keys()) if expected.get(name)!=actual.get(name)]
 if changes:raise ValueError('Source inventory mismatch: '+', '.join(changes))
 version=(ROOT/'VERSION').read_text().strip()
 if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?',version):raise ValueError('Invalid distribution VERSION')
 if f'## [{version}]' not in (ROOT/'CHANGELOG.md').read_text():raise ValueError('Current version missing from changelog')
 if version not in (ROOT/'README.md').read_text():raise ValueError('Current version missing from README')
 header=(ROOT/'include/MithrilHook.h').read_text()
 declarations=set(re.findall(r'WINAPI\s+(MTH_\w+)\s*\(',header))
 exports=set(re.findall(r'\bMTH_\w+\b',(ROOT/'dll_resources/MithrilHook.def').read_text()))
 if declarations!=exports:raise ValueError('Public declarations and exports differ')
 if (ROOT/'include/MinHook.h').exists():raise ValueError('Legacy compatibility header is forbidden')
 for path in [*list((ROOT/'src').rglob('*.c')),*list((ROOT/'src').rglob('*.h')),ROOT/'include/MithrilHook.h']:
  source=path.read_text()
  if re.search(r'\bMH_\w+|\bMINHOOK_\w+',source):raise ValueError('Legacy active identifier: '+str(path))
 if '#if defined(MTH_SAFE_FREEZE)' in (ROOT/'src/hook.c').read_text():
  raise ValueError('Production core must not retain an optional weaker engine')
 print(f'PASS: {len(actual)} source files, {len(exports)} MTH exports, {version}, strict-only core and no legacy API aliases')
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--refresh',action='store_true');args=parser.parse_args()
 if args.refresh:
  (ROOT/MANIFEST).write_text(json.dumps({'schema':'mithrilhook.source.v1','files':members()},indent=2)+'\n')
 else:verify()
if __name__=='__main__':main()
