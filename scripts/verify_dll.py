#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check PE exports and product identity without a third-party PE package."""
import argparse
from pathlib import Path
import re
import struct
ROOT=Path(__file__).resolve().parents[1]
def check(path):
 data=Path(path).read_bytes()
 def u16(offset):return struct.unpack_from('<H',data,offset)[0]
 def u32(offset):return struct.unpack_from('<I',data,offset)[0]
 if data[:2]!=b'MZ':raise ValueError('Missing MZ signature')
 pe=u32(0x3c)
 if data[pe:pe+4]!=b'PE\0\0':raise ValueError('Missing PE signature')
 sections=u16(pe+6);optional=pe+24;magic=u16(optional)
 if magic not in (0x10b,0x20b):raise ValueError('Unsupported PE optional header')
 directories=optional+(112 if magic==0x20b else 96)
 exports_rva=u32(directories)
 table=optional+u16(pe+20)
 def position(rva):
  for index in range(sections):
   at=table+40*index
   virtual_size,virtual_address,raw_size,raw_pointer=struct.unpack_from('<IIII',data,at+8)
   if virtual_address<=rva<virtual_address+max(virtual_size,raw_size):
    result=raw_pointer+rva-virtual_address
    if result>=len(data):raise ValueError('RVA outside file')
    return result
  raise ValueError('Unmapped RVA')
 at=position(exports_rva);function_count=u32(at+20);count=u32(at+24);names=position(u32(at+32));actual=set()
 for index in range(count):
  name_at=position(u32(names+index*4));end=data.index(b'\0',name_at)
  actual.add(data[name_at:end].decode('ascii'))
 expected=set(re.findall(r'WINAPI\s+(MTH_\w+)\s*\(',(ROOT/'include/MithrilHook.h').read_text()))
 if actual!=expected or function_count!=len(expected):raise ValueError(f'Unexpected public exports: {actual^expected}, total={function_count}')
 if 'MithrilHook'.encode('utf-16-le') not in data:raise ValueError('Missing MithrilHook product resource')
 if 'MinHook DLL'.encode('utf-16-le') in data:raise ValueError('Inherited product resource remains')
 version=(ROOT/'VERSION').read_text().strip()
 parsed=re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?',version)
 if not parsed or version.encode('utf-16-le') not in data:raise ValueError('DLL version string does not match VERSION')
 signature=data.find(struct.pack('<I',0xfeef04bd))
 if signature<0 or signature+52>len(data):raise ValueError('Missing fixed version resource')
 fixed=struct.unpack_from('<13I',data,signature)
 major,minor,patch=map(int,parsed.group(1,2,3))
 if any(x>0xffff for x in (major,minor,patch)):raise ValueError('VERSION exceeds Windows resource limits')
 expected_fixed=((major<<16)|minor,patch<<16)
 if fixed[2:4]!=expected_fixed or fixed[4:6]!=expected_fixed:raise ValueError('DLL numeric resource version differs from VERSION')
 if bool(fixed[7]&2)!=bool(parsed.group(4)):raise ValueError('DLL prerelease flag differs from VERSION')
 print(f'PASS: {len(actual)} exact MTH exports, MithrilHook identity and {version} resource metadata')
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('dll');args=parser.parse_args();check(args.dll)
