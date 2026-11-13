#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Generate bounded test-only mutations and require their exact failure oracle."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
GUARD='''\n    if (g_hHeap != NULL && (g_shutdownPending || !RetryRetainedThreadOwnership()))
    {
        LeaveSpinLock();
        return MTH_ERROR_MEMORY_PROTECT;
    }'''
CASES={
 'create':('MTH_STATUS WINAPI MTH_CreateHook(', 'FAIL: new hook creation cannot bypass retained cleanup'),
 'remove':('MTH_STATUS WINAPI MTH_RemoveHook(', 'FAIL: disabled removal cannot retire trampoline under unresolved ownership'),
 'enable':('static MTH_STATUS EnableHook(', 'FAIL: already-disabled mutation must report pending cleanup'),
 'queue':('static MTH_STATUS QueueHook(', 'FAIL: queue mutation cannot bypass retained cleanup'),
 'apply':('MTH_STATUS WINAPI MTH_ApplyQueued(', 'FAIL: no-op apply must not hide unresolved owner'),
}
EXTRA={
 'overlap':('static BOOL IsPatchIntervalAvailable(ULONG_PTR start, SIZE_T size)\n{','TRUE','FAIL: conflicting hook creation refuses before publishing an original'),
 'reconcile':('static BOOL ReconcileThreadIPs(PFROZEN_THREADS pThreads)\n{','TRUE','FAIL: partial disable maps peers only for physically written targets'),
 'coverage':('static MTH_STATUS VerifyFrozenThreadCoverage(PFROZEN_THREADS pThreads)\n{','MTH_OK','FAIL: peer born after enumeration rejects mutation before patching'),
 'unwind':('static BOOL IsRelocationUnwindSafe(const TRAMPOLINE *ct)\n{','TRUE',None),
}
CALL_GUARD='''            if (dest >= (ULONG_PTR)ct->pTarget &&
                dest - (ULONG_PTR)ct->pTarget < sizeof(JMP_REL))
                return FALSE;
'''
X87_GUARD='''            if (hs.opcode >= 0xD8 && hs.opcode <= 0xDF)
                return FALSE;
'''
TRAMPOLINE_CONTROLS={'internal-call':'FAIL: internal CALL refuses before original publication',
 'x87':'FAIL: x87 producer refuses before original publication'}
def prepare(output):
 output=Path(output).resolve()
 if not output.is_relative_to((ROOT/'build').resolve()):
  raise ValueError('Controls must be generated under the local build tree')
 source=(ROOT/'src/hook.c').read_text()
 expected=json.loads((ROOT/'metadata/SOURCE_MANIFEST.json').read_text())['files']['src/hook.c']
 if hashlib.sha256((ROOT/'src/hook.c').read_bytes()).hexdigest()!=expected:
  raise ValueError('Control source does not match the reviewed inventory')
 output.mkdir(parents=True,exist_ok=True)
 for mode,(signature,_) in CASES.items():
  if source.count(signature)!=1:raise ValueError('Ambiguous entry signature: '+mode)
  start=source.index(signature);end=source.index('\n}',start)
  body=source[start:end]
  if body.count(GUARD)!=1:raise ValueError('Missing unique entry guard: '+mode)
  result=source[:start]+body.replace(GUARD,'',1)+source[end:]
  (output/(mode+'.c')).write_text(result)
 for mode,(signature,value,_) in EXTRA.items():
  if source.count(signature)!=1:raise ValueError('Missing unique safety helper: '+mode)
  (output/(mode+'.c')).write_text(source.replace(signature,signature+'\n    return '+value+';',1))
 anchor='ip = hook->isEnabled ? FindNewIP(hook, desired) : FindOldIP(hook, desired);'
 if source.count(anchor)!=1:raise ValueError('Missing unique disable-action anchor')
 (output/'stale.c').write_text(source.replace(anchor,'ip = hook->isEnabled ? FindNewIP(hook, desired) : 0;',1))
 trampoline=(ROOT/'src/trampoline.c').read_bytes()
 expected=json.loads((ROOT/'metadata/SOURCE_MANIFEST.json').read_text())['files']['src/trampoline.c']
 if hashlib.sha256(trampoline).hexdigest()!=expected:
  raise ValueError('Relocator control source does not match the reviewed inventory')
 trampoline=trampoline.decode()
 if trampoline.count(CALL_GUARD)!=1:raise ValueError('Missing unique internal CALL refusal')
 (output/'internal-call.c').write_text(trampoline.replace(CALL_GUARD,'',1))
 if trampoline.count(X87_GUARD)!=1:raise ValueError('Missing unique x87 relocation refusal')
 (output/'x87.c').write_text(trampoline.replace(X87_GUARD,'',1))
def run(mode,command):
 result=subprocess.run(command,capture_output=True,text=True,timeout=35)
 print(result.stdout,end='');print(result.stderr,end='',file=sys.stderr)
 failures=[s for s in (result.stdout+'\n'+result.stderr).splitlines() if s.startswith('FAIL:')]
 if mode=='unwind':
  lines=(result.stdout+'\n'+result.stderr).splitlines()
  if result.returncode!=42 or failures or 'UNWIND_MISMATCH: relocated stack-changing prologue has no registered function entry' not in lines or 'UNWIND_CLEANUP: PASS hook, function table, allocation and handles retired' not in lines:
   raise RuntimeError('Unwind control did not prove the precise metadata mismatch and complete cleanup')
  print('PASS: exact negative control unwind, complete cleanup');return
 if mode=='stale':
  lines=(result.stdout+'\n'+result.stderr).splitlines()
  if result.returncode!=42 or failures or 'SINGLE_DISABLE_IP_MISMATCH: real IP retained the trampoline/relay address' not in lines or 'REAL_PEER_CLEANUP: PASS original context restored, worker joined, handle count restored' not in lines:
   raise RuntimeError('Stale-action control did not prove the precise mismatch and complete cleanup')
  print('PASS: exact negative control stale, complete cleanup');return
 expected=TRAMPOLINE_CONTROLS[mode] if mode in TRAMPOLINE_CONTROLS else EXTRA[mode][2] if mode in EXTRA else CASES[mode][1]
 if result.returncode!=1 or failures!=[expected]:
  raise RuntimeError('Control did not fail only at its required assertion: '+mode)
 print('PASS: exact negative control '+mode)
def main():
 parser=argparse.ArgumentParser(description=__doc__)
 sub=parser.add_subparsers(dest='operation',required=True)
 p=sub.add_parser('prepare');p.add_argument('--output',required=True)
 p=sub.add_parser('run');p.add_argument('--mode',choices=[*CASES,*EXTRA,*TRAMPOLINE_CONTROLS,"stale"],required=True);p.add_argument('command',nargs=argparse.REMAINDER)
 args=parser.parse_args()
 if args.operation=='prepare':prepare(args.output)
 else:
  command=args.command[1:] if args.command[:1]==['--'] else args.command
  if not command:parser.error('A control executable is required')
  run(args.mode,command)
if __name__=='__main__':main()
