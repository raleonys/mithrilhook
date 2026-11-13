# SPDX-License-Identifier: GPL-3.0-only
"""Fetch immutable benchmark-only inputs; never modify production/vendor sources."""
import hashlib,json,shutil,subprocess,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def run(*args):return subprocess.check_output(args,text=True).strip()
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def prepare():
 lock=json.loads((ROOT/'metadata/BENCHMARK_SOURCES.json').read_text())
 sources=ROOT/'build/bench-sources';sources.mkdir(parents=True,exist_ok=True)
 receipt={'lock_sha256':sha(ROOT/'metadata/BENCHMARK_SOURCES.json'),'repositories':{},'files':{}}
 for name,item in lock['repositories'].items():
  dest=sources/name
  if not (dest/'.git').exists():
   run('git','init',str(dest));run('git','-C',str(dest),'config','core.autocrlf','false');run('git','-C',str(dest),'config','core.eol','lf');run('git','-C',str(dest),'fetch','--depth=1','https://github.com/'+item['repository']+'.git',item['commit'])
   run('git','-C',str(dest),'checkout','--detach','FETCH_HEAD')
  if run('git','-C',str(dest),'rev-parse','HEAD')!=item['commit'] or run('git','-C',str(dest),'status','--porcelain'):
   raise ValueError('Benchmark input is wrong or dirty: '+name)
  receipt['repositories'][name]=item
  for relative in run('git','-C',str(dest),'ls-files','-z').split('\0'):
   path=dest/relative
   if relative and path.is_file():receipt['files'][str(path.relative_to(ROOT))]=sha(path)
 prepared=ROOT/'build/bench-prepared';prepared.mkdir(parents=True,exist_ok=True)
 dest=prepared/'patched'
 if dest.exists():shutil.rmtree(dest)
 for directory in ['src','include']:shutil.copytree(sources/'patched'/directory,dest/directory)
 patch=prepared/'PatchHookRelocator.cmake'
 patch.write_bytes(urllib.request.urlopen(lock['patched_relocator']['url'],timeout=60).read())
 if sha(patch)!=lock['patched_relocator']['sha256']:raise ValueError('Relocator patch digest mismatch')
 run('cmake','-DMINHOOK_HOOK_C='+str(dest/'src/hook.c'),'-P',str(patch))
 if sha(dest/'src/trampoline.c')!=lock['patched_relocator']['output_sha256']:raise ValueError('Prepared baseline digest mismatch')
 for path in sorted(prepared.rglob('*')):
  if path.is_file() and path.name!='inputs.json':receipt['files'][str(path.relative_to(ROOT))]=sha(path)
 (prepared/'inputs.json').write_text(json.dumps(receipt,indent=2)+'\n')
 print('PASS: six immutable external inputs and exact SAFE-FREEZE/Citrine relocation baseline')
if __name__=='__main__':prepare()
