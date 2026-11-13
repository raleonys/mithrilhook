# SPDX-License-Identifier: GPL-3.0-only
"""Run isolated native candidates and audit retained samples without executing them."""
import argparse,collections,copy,hashlib,json,math,os,platform,random,re,shutil,statistics,subprocess,sys,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if sys.flags.optimize:raise RuntimeError('The auditor requires Python assertion checks enabled')
ENGINES=['mithrilhook','official','official_current','patched','m417z','detours','slim','mhd']
CASES=[(hooks,peers,0) for hooks in (1,4,11,32,64) for peers in (0,1,4,16,32,64)]
CASES += [(hooks,0,callers) for hooks in (1,11) for callers in (1,4,16,64)]
ROUNDS=7
CALL_METRICS={'direct_call','detour_only','detour_original','original_trampoline'}
CONCURRENT='concurrent_detour_original'
COMMON={'activate_batch','complete_install','disable_batch','complete_remove','single_disable','single_enable','queued_or_transaction_disable','queued_or_transaction_enable'}
SEPARATE=set(ENGINES)-{'detours','slim'}
PROBES=['leaf','rip_load','relative_jump','relative_call','conditional_branch','loop_branch','hotpatch_short','registered_nonleaf','interior_entry','frame_byte_ch','handler_body','prefixed_call','prefixed_jump']+[f'prefixed_jcc_{n}' for n in range(16)]
PROBE_ACCEPT={'leaf','rip_load','relative_jump','relative_call','conditional_branch','hotpatch_short','registered_nonleaf','frame_byte_ch'}
def validate_probe(engine,case,result,bits,receipt):
 if result['returncode']!=0:
  assert result['status']=='FAILED',result
  if engine=='mithrilhook':raise AssertionError('Current core failed compatibility case: '+case)
  return
 row=result['row'];status=row['status'];assert result['status']==status
 if status=='NOT_APPLICABLE':
  assert bits==32 and case in {'registered_nonleaf','interior_entry','frame_byte_ch','handler_body'}
  return
 assert row['engine']==engine and row['case']==case and row['cleanup'] is True
 assert row['source_digest']==receipt['source_digest'] and row['input_digest']==receipt['input_digest']
 assert status in {'CALL_BEHAVIOR_VERIFIED','CREATION_ONLY_NOT_SEMANTICALLY_VALIDATED','API_REJECTED'}
 if engine=='mithrilhook':
  assert status==('CALL_BEHAVIOR_VERIFIED' if case in PROBE_ACCEPT else 'API_REJECTED'),(case,row)
  if bits==64 and case in {'relative_call','registered_nonleaf','frame_byte_ch'}:assert row['unwind']=='VERIFIED_EXACT_CALLER'

API_TARGETS={'connect','RegOpenKeyExA','RegOpenKeyExW','RegCloseKey','RegQueryValueExA','RegQueryValueExW','CreateProcessA','CreateProcessW','SHGetFolderPathA','SHGetFolderPathW','CryptQueryObject'}
def normalized(value):
 if isinstance(value,float):return round(value,8)
 if isinstance(value,list):return [normalized(item) for item in value]
 if isinstance(value,dict):return {key:normalized(item) for key,item in value.items()}
 return value

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def unique_pairs(pairs):
 result={}
 for key,value in pairs:
  if key in result:raise ValueError('Duplicate JSON key: '+key)
  result[key]=value
 return result
def bad_constant(value):raise ValueError('Nonfinite JSON: '+value)
def read(path):return json.loads(Path(path).read_text(),object_pairs_hook=unique_pairs,parse_constant=bad_constant)
def write(path,obj):Path(path).write_text(json.dumps(obj,indent=2,allow_nan=False)+'\n')
def percent(values,p):return sorted(values)[max(0,math.ceil(p*len(values))-1)]
def paired_interval(ratios):
 logs=[math.log(x) for x in ratios];rng=random.Random(19473)
 samples=sorted(math.exp(sum(rng.choices(logs,k=len(logs)))/len(logs)) for _ in range(4000))
 return {'geomean':math.exp(statistics.mean(logs)),'low95':percent(samples,.025),'high95':percent(samples,.975),'independent_rounds':len(logs)}
def validate_child(entry,receipt):
 rows=entry['rows'];env=rows[0];end=rows[-1]
 assert env['type']=='environment' and env['engine']==entry['engine']
 assert env['source_digest']==receipt['source_digest'] and env['input_digest']==receipt['input_digest']
 assert env['compiler']==receipt['compiler'] and env['bits']==receipt['bits'] and env['bits'] in (32,64)
 assert (env['hooks'],env['peers'],env['callers'])==(entry['hooks'],entry['peers'],entry['callers']) and isinstance(env['qpc_frequency'],int) and env['qpc_frequency']>0
 assert env['timer_overhead_ticks']>=0 and env['affinity']>0
 assert end=={'type':'complete','cycles':3,'hooks':entry['hooks'],'peers':entry['peers'],'callers':entry['callers'],'handle_baseline':end['handle_baseline'],'handle_final':end['handle_final'],'errors':0}
 assert end['handle_baseline']==end['handle_final']
 metrics=COMMON|CALL_METRICS|({CONCURRENT} if entry['callers'] else set())|({'initialize','create','retire'} if entry['engine'] in SEPARATE else set())
 grouped=collections.defaultdict(list);resources=[]
 for row in rows[1:-1]:
  if row['type']=='resources':resources.append(row);continue
  assert row['type']=='sample' and row['metric'] in metrics
  assert isinstance(row['ticks'],int) and row['ticks']>=0
  assert row['operations']==(500000*entry['callers'] if row['metric']==CONCURRENT else 500000 if row['metric'] in CALL_METRICS else 1 if row['metric'] in {'initialize','single_enable','single_disable'} else entry['hooks'])
  assert isinstance(row['sample'],int)
  if row['metric'] in CALL_METRICS or row['metric']==CONCURRENT:
   n=500000;inc=9 if row['metric'] in {'detour_only','detour_original',CONCURRENT} else 7
   groups,remainder=divmod(n,1024);expected=groups*1023*1024//2+remainder*(remainder-1)//2+n*inc
   assert row['checksum']==expected*(entry['callers'] if row['metric']==CONCURRENT else 1)
  else:assert row['checksum']==0
  grouped[row['metric']].append(row)
 assert set(grouped)==metrics
 for name,items in grouped.items():assert sorted(r['sample'] for r in items)==list(range(7 if name in CALL_METRICS else 3))
 assert len(resources)==3 and sorted(r['cycle'] for r in resources)==[0,1,2]
 for row in resources:
  assert all(isinstance(v,int) and v>=0 for k,v in row.items() if k!='type')
 return env,grouped,resources

def analyze(entries,receipts,rounds):
 assert len(entries)==len(ENGINES)*len(CASES)*rounds
 seen=set();values=collections.defaultdict(list);round_values=collections.defaultdict(list);resources=collections.defaultdict(list)
 for entry in entries:
  key=(entry['engine'],entry['hooks'],entry['peers'],entry['callers'],entry['round']);assert key not in seen;seen.add(key)
  assert entry['engine'] in ENGINES and (entry['hooks'],entry['peers'],entry['callers']) in CASES and 0<=entry['round']<rounds
  env,grouped,memory=validate_child(entry,receipts[entry['engine']])
  for metric,items in grouped.items():
   for row in items:
    name=metric if metric in CALL_METRICS or metric==CONCURRENT else metric+('_cold' if row['sample']==0 else '_warm')
    cell=(entry['engine'],entry['hooks'],entry['peers'],entry['callers'],name)
    value=row['ticks']*1e9/env['qpc_frequency']/row['operations']
    assert math.isfinite(value) and value>=0
    values[cell].append(value);round_values[cell+(entry['round'],)].append(value)
  for row in memory:resources[(entry['engine'],entry['hooks'],entry['peers'],entry['callers'])].append(row)
 summary=[]
 for (engine,hooks,peers,callers,metric),samples in sorted(values.items()):
  medians=[statistics.median(round_values[(engine,hooks,peers,callers,metric,r)]) for r in range(rounds)]
  baseline=[statistics.median(round_values[('mithrilhook',hooks,peers,callers,metric,r)]) for r in range(rounds)]
  item={'engine':engine,'hooks':hooks,'peers':peers,'callers':callers,'metric':metric,'samples':len(samples),'median_ns':statistics.median(samples),'p95_batch_ns':percent(samples,.95),'p99_batch_ns':percent(samples,.99),'round_medians_ns':medians,'unit':'ns_per_concurrent_completed_call' if metric==CONCURRENT else 'ns_per_call_batch_average' if metric in CALL_METRICS else 'ns_per_engine' if metric.startswith(('initialize','single_enable','single_disable')) else 'ns_per_hook'}
  if all(x>0 for x in medians+baseline):item['ratio_to_mithrilhook']=paired_interval([a/b for a,b in zip(medians,baseline)])
  summary.append(item)
 memory=[]
 for (engine,hooks,peers,callers),rows in sorted(resources.items()):
  memory.append({'engine':engine,'hooks':hooks,'peers':peers,'callers':callers,'samples':len(rows),'exec_installed_delta_median':statistics.median(r['exec_installed']-r['exec_before'] for r in rows),'exec_retired_delta_median':statistics.median(r['exec_after']-r['exec_before'] for r in rows),'private_installed_delta_median':statistics.median(r['private_installed']-r['private_before'] for r in rows),'cpu_install_zero_samples':sum(r['cpu_install_100ns']==0 for r in rows),'cpu_remove_zero_samples':sum(r['cpu_remove_100ns']==0 for r in rows)})
 return normalized({'schema':'mithrilhook.benchmark-summary.v1','rounds':rounds,'children':len(entries),'timings':summary,'resources':memory,'limits':['leaf fixtures; idle owned peers; no application/game acceptance','p95/p99 describe batch samples, not individual-call population tails','seven rounds on a hosted VM do not establish cross-host speed superiority','adapter thread and retirement contracts differ; no equivalent-safety ranking']})

def check_controls():
 # The real child corruption control runs separately under Windows. These
 # retained-evidence mutations ensure hashes alone cannot conceal false data.
 entry={'engine':'mithrilhook','hooks':1,'peers':0,'callers':0,'round':0,'rows':[{'type':'environment','engine':'mithrilhook','source_digest':'s','input_digest':'i','compiler':'c','bits':64,'hooks':1,'peers':0,'callers':0,'qpc_frequency':10000000,'timer_overhead_ticks':0,'affinity':1}]}
 for name in sorted(COMMON|CALL_METRICS|{'initialize','create','retire'}):
  for index in range(7 if name in CALL_METRICS else 3):
   n=500000 if name in CALL_METRICS else 1;g,r=divmod(n,1024);inc=9 if name in {'detour_only','detour_original'} else 7
   checksum=g*1023*1024//2+r*(r-1)//2+n*inc if name in CALL_METRICS else 0
   entry['rows'].append({'type':'sample','metric':name,'sample':index,'ticks':100,'operations':n,'checksum':checksum})
 for c in range(3):entry['rows'].append(dict(type='resources',cycle=c,**{k:0 for k in ['private_before','private_installed','private_after','exec_before','exec_installed','exec_after','cpu_install_100ns','cpu_remove_100ns']}))
 entry['rows'].append(dict(type='complete',cycles=3,hooks=1,peers=0,callers=0,handle_baseline=4,handle_final=4,errors=0))
 receipt={'source_digest':'s','input_digest':'i','compiler':'c','bits':64};validate_child(entry,receipt)
 for field in ['checksum','operations','sample']:
  bad=copy.deepcopy(entry);row=next(r for r in bad['rows'] if r.get('metric')=='direct_call');row[field]+=1
  try:validate_child(bad,receipt)
  except (AssertionError,KeyError,ValueError):continue
  raise AssertionError('Corrupt sample accepted: '+field)
 print('PASS: offline evidence corruption controls')

def audit(output):
 output=Path(output);manifest=read(output/'run.json')
 assert manifest['schema']=='mithrilhook.benchmark-run.v2'
 assert sha(output/'VERSION')==read(output/'SOURCE_MANIFEST.json')['files']['VERSION']
 assert manifest['candidate_version']==(output/'VERSION').read_text().strip()
 assert manifest['engines']==ENGINES and manifest['cases']==[list(c) for c in CASES] and manifest['rounds']==ROUNDS
 receipts={name:read(output/'binaries'/f'bench_{name}.receipt.json') for name in ENGINES}
 for name,receipt in receipts.items():
  assert sha(output/'binaries'/f'bench_{name}.exe')==receipt['exe_sha256']
  assert receipt['source_digest']==manifest['source_digest'] and receipt['input_digest']==manifest['input_digest'] and receipt['configuration']=='Release'
 assert sha(output/'inputs.json')==manifest['input_digest'] and sha(output/'SOURCE_MANIFEST.json')==manifest['source_digest']
 api_receipt=read(output/'binaries/api_mithrilhook.receipt.json')
 assert sha(output/'binaries/api_mithrilhook.exe')==api_receipt['exe_sha256']
 assert api_receipt['source_digest']==manifest['source_digest'] and api_receipt['input_digest']==manifest['input_digest']
 for stream in ['stdout','stderr']:assert sha(output/'raw'/('application-targets.'+stream))==manifest['application_targets'][stream+'_sha256']
 api_statuses=re.findall(r'^TARGET_PROBE name=(\w+) status=(\w+) enabled=0 executed=0$',(output/'raw/application-targets.stdout').read_text(),re.M)
 assert len(api_statuses)==11 and {name for name,status in api_statuses}==API_TARGETS and dict(api_statuses)==manifest['application_targets']['classifications']
 assert manifest['application_targets']['returncode']==0 and all(status in {'MTH_OK','MTH_ERROR_UNSUPPORTED_FUNCTION'} for name,status in api_statuses)
 probe_receipts={name:read(output/'binaries'/f'probe_{name}.receipt.json') for name in ENGINES}
 assert manifest['probe_cases']==PROBES and len(manifest['probes'])==len(ENGINES)*len(PROBES)
 seen_probes=set()
 for engine,receipt in probe_receipts.items():
  assert sha(output/'binaries'/f'probe_{engine}.exe')==receipt['exe_sha256']
  assert receipt['source_digest']==manifest['source_digest'] and receipt['input_digest']==manifest['input_digest']
 for result in manifest['probes']:
  engine,case=result['engine'],result['case'];assert engine in ENGINES and case in PROBES and (engine,case) not in seen_probes;seen_probes.add((engine,case))
  for stream in ['stdout','stderr']:assert sha(output/'raw'/f'probe-{engine}-{case}.{stream}')==result[stream+'_sha256']
  if result['returncode']==0:assert json.loads((output/'raw'/f'probe-{engine}-{case}.stdout').read_text(),object_pairs_hook=unique_pairs,parse_constant=bad_constant)==result['row']
  validate_probe(engine,case,result,probe_receipts[engine]['bits'],probe_receipts[engine])
 entries=[]
 assert len(manifest['children'])==len(ENGINES)*len(CASES)*ROUNDS
 for item in manifest['children']:
  path=output/'raw'/item['file'];assert path.parent==output/'raw' and path.suffix=='.json'
  assert sha(path)==item['sha256'];entry=read(path);
  for stream in ['stdout','stderr']:assert sha(path.with_suffix('.'+stream))==item[stream+'_sha256']
  assert [json.loads(line,object_pairs_hook=unique_pairs,parse_constant=bad_constant) for line in path.with_suffix('.stdout').read_text().splitlines() if line]==entry['rows']
  assert entry['run_id']==manifest['run_id'];assert entry['exe_sha256']==receipts[entry['engine']]['exe_sha256'];entries.append(entry)
 assert manifest['seed']==19473
 rng=random.Random(manifest['seed']);schedule=[]
 for round_number in range(ROUNDS):
  cases=list(CASES);rng.shuffle(cases)
  for hooks,peers,callers in cases:
   order=list(ENGINES);rng.shuffle(order)
   schedule.extend((name,hooks,peers,callers,round_number) for name in order)
 assert [(e['engine'],e['hooks'],e['peers'],e['callers'],e['round']) for e in entries]==schedule
 expected=analyze(entries,receipts,ROUNDS)
 assert read(output/'summary.json')==expected
 assert len(manifest['controls'])==len(ENGINES) and {c['engine'] for c in manifest['controls']}==set(ENGINES) and all(c['returncode']==1 and c['expected_failure']=='complete timed-call checksum' for c in manifest['controls'])
 for control in manifest['controls']:
  engine=control['engine'];assert engine in ENGINES
  for stream in ['stdout','stderr']:assert sha(output/'raw'/f'control-{engine}.{stream}')==control[stream+'_sha256']
  assert [line.split(' error=')[0] for line in (output/'raw'/f'control-{engine}.stderr').read_text().splitlines() if line.startswith('FAIL:')]==['FAIL: complete timed-call checksum']
 print('PASS: offline audit of source/build identities, complete recipe, checksums, raw hashes and recomputed statistics')
 return expected

def measure(build,output):
 if sys.platform!='win32':raise RuntimeError('Native Windows is required for performance execution')
 subprocess.run([sys.executable,str(ROOT/'scripts/verify_sources.py')],check=True)
 top=subprocess.check_output(['git','-C',str(ROOT),'rev-parse','--show-toplevel'],text=True).strip()
 assert Path(top).resolve()==ROOT and not subprocess.check_output(['git','-C',str(ROOT),'status','--porcelain'],text=True).strip()
 commit=subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip()
 build=Path(build).resolve();output=Path(output).resolve();output.mkdir(parents=True,exist_ok=False)
 (output/'raw').mkdir();(output/'binaries').mkdir()
 inputs=ROOT/'build/bench-prepared/inputs.json';input_record=read(inputs)
 for name,digest in input_record['files'].items():assert sha(ROOT/name)==digest,name
 assert input_record['lock_sha256']==sha(ROOT/'metadata/BENCHMARK_SOURCES.json')
 shutil.copy2(inputs,output/'inputs.json');shutil.copy2(ROOT/'metadata/SOURCE_MANIFEST.json',output/'SOURCE_MANIFEST.json')
 shutil.copy2(ROOT/'VERSION',output/'VERSION')
 receipts={}
 for engine in ENGINES:
  for prefix in ['bench','probe']:
   exe=build/'Release'/f'{prefix}_{engine}.exe';receipt=read(exe.with_suffix('.receipt.json'))
   assert receipt['exe_sha256']==sha(exe) and receipt['source_digest']==sha(ROOT/'metadata/SOURCE_MANIFEST.json') and receipt['input_digest']==sha(inputs)
   if prefix=='bench':receipts[engine]=receipt
   shutil.copy2(exe,output/'binaries'/exe.name);shutil.copy2(exe.with_suffix('.receipt.json'),output/'binaries'/exe.with_suffix('.receipt.json').name)
 # Include redistribution notices with the retained benchmark binaries.
 for relative in input_record['files']:
  path=ROOT/relative
  if any(token in path.name.lower() for token in ('license','copying','notice')):
   dest=output/'licenses'/Path(relative).relative_to('build');dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,dest)
 for name in ['LICENSE','LICENSE.txt','LICENSE.SAFE_FREEZE','THIRD_PARTY_NOTICES.txt','metadata/BENCHMARK_SOURCES.json']:
  dest=output/'licenses'/'mithrilhook'/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,dest)
 manifest={'schema':'mithrilhook.benchmark-run.v2','candidate_version':(ROOT/'VERSION').read_text().strip(),'run_id':str(uuid.uuid4()),'commit':commit,'source_digest':sha(ROOT/'metadata/SOURCE_MANIFEST.json'),'input_digest':sha(inputs),'host':{'platform':platform.platform(),'processor':platform.processor(),'logical_processors':os.cpu_count(),'power_policy':subprocess.run(['powercfg','/getactivescheme'],capture_output=True,text=True).stdout.strip()},'engines':ENGINES,'cases':CASES,'rounds':ROUNDS,'seed':19473,'children':[],'controls':[],'probe_cases':PROBES,'probes':[]}
 api_exe=build/'Release/api_mithrilhook.exe';api_receipt=read(api_exe.with_suffix('.receipt.json'))
 assert api_receipt['exe_sha256']==sha(api_exe) and api_receipt['source_digest']==manifest['source_digest'] and api_receipt['input_digest']==manifest['input_digest']
 shutil.copy2(api_exe,output/'binaries'/api_exe.name);shutil.copy2(api_exe.with_suffix('.receipt.json'),output/'binaries'/api_exe.with_suffix('.receipt.json').name)
 result=subprocess.run([str(api_exe)],capture_output=True,text=True,timeout=90)
 for stream in ['stdout','stderr']:(output/'raw'/('application-targets.'+stream)).write_text(getattr(result,stream))
 assert result.returncode==0,('actual API creation probe failed',result.stderr)
 statuses=re.findall(r'^TARGET_PROBE name=(\w+) status=(\w+) enabled=0 executed=0$',result.stdout,re.M)
 assert len(statuses)==11 and {name for name,status in statuses}==API_TARGETS
 manifest['application_targets']={'classifications':dict(statuses),'returncode':0,'stdout_sha256':sha(output/'raw/application-targets.stdout'),'stderr_sha256':sha(output/'raw/application-targets.stderr')}
 write(output/'run.json',manifest)
 print('Actual API create/remove coverage: '+str(sum(status=='MTH_OK' for name,status in statuses))+'/11; no target enabled/executed',flush=True)
 for engine in ENGINES:
  receipt=read(build/'Release'/f'probe_{engine}.receipt.json')
  for case in PROBES:
   result=subprocess.run([str(build/'Release'/f'probe_{engine}.exe'),case],capture_output=True,text=True,timeout=45)
   item={'engine':engine,'case':case,'returncode':result.returncode,'status':'FAILED'}
   for stream in ['stdout','stderr']:
    path=output/'raw'/f'probe-{engine}-{case}.{stream}';path.write_text(getattr(result,stream));item[stream+'_sha256']=sha(path)
   if result.returncode==0:item['row']=json.loads(result.stdout,object_pairs_hook=unique_pairs,parse_constant=bad_constant);item['status']=item['row']['status']
   manifest['probes'].append(item);write(output/'run.json',manifest)
   validate_probe(engine,case,item,receipt['bits'],receipt)
 print('Completed source-form/creation/unwind compatibility matrix',flush=True)
 for engine in ENGINES:
  result=subprocess.run([str(build/'Release'/f'bench_{engine}.exe'),'1','0','corrupt-checksum'],capture_output=True,text=True,timeout=60)
  assert result.returncode==1 and [s.split(' error=')[0] for s in result.stderr.splitlines() if s.startswith('FAIL:')]==['FAIL: complete timed-call checksum'],(engine,result.returncode,result.stderr)
  (output/'raw'/f'control-{engine}.stdout').write_text(result.stdout);(output/'raw'/f'control-{engine}.stderr').write_text(result.stderr)
  manifest['controls'].append({'engine':engine,'returncode':result.returncode,'expected_failure':'complete timed-call checksum','stdout_sha256':sha(output/'raw'/f'control-{engine}.stdout'),'stderr_sha256':sha(output/'raw'/f'control-{engine}.stderr')})
 entries=[];rng=random.Random(manifest['seed'])
 for round_number in range(ROUNDS):
  cases=list(CASES);rng.shuffle(cases)
  for hooks,peers,callers in cases:
   order=list(ENGINES);rng.shuffle(order)
   for engine in order:
    command=[str(build/'Release'/f'bench_{engine}.exe'),str(hooks),str(peers),str(callers)]
    result=subprocess.run(command,capture_output=True,text=True,timeout=120)
    stem=f'r{round_number}-h{hooks}-p{peers}-c{callers}-{engine}'
    (output/'raw'/(stem+'.stdout')).write_text(result.stdout);(output/'raw'/(stem+'.stderr')).write_text(result.stderr)
    if result.returncode!=0:raise RuntimeError(f'Failed native child {stem}: {result.returncode}\n{result.stderr}')
    entry={'run_id':manifest['run_id'],'engine':engine,'hooks':hooks,'peers':peers,'callers':callers,'round':round_number,'exe_sha256':receipts[engine]['exe_sha256'],'rows':[json.loads(line,object_pairs_hook=unique_pairs,parse_constant=bad_constant) for line in result.stdout.splitlines() if line]}
    validate_child(entry,receipts[engine]);path=output/'raw'/(stem+'.json');write(path,entry)
    manifest['children'].append({'file':path.name,'sha256':sha(path),'stdout_sha256':sha(output/'raw'/(stem+'.stdout')),'stderr_sha256':sha(output/'raw'/(stem+'.stderr'))});entries.append(entry)
    write(output/'run.json',manifest)
  print(f'Completed paired round {round_number+1}/{ROUNDS}',flush=True)
 write(output/'summary.json',analyze(entries,receipts,ROUNDS));write(output/'run.json',manifest)
 print_report(output)

def print_report(output):
 summary=read(Path(output)/'summary.json');rows=summary['timings']
 manifest=read(Path(output)/'run.json')
 lines=['# Native hook-engine comparison','',f"MithrilHook candidate version: `{manifest['candidate_version']}`.",'',f"Source: `{manifest['commit']}`; compiler: `{read(Path(output)/'binaries/bench_mithrilhook.receipt.json')['compiler']}`.",f"Host: {manifest['host']['platform']}; {manifest['host']['processor']}; logical processors: {manifest['host']['logical_processors']}.",'',f"{summary['children']} positive children; {summary['rounds']} paired rounds; {len(CASES)} workload cases.",'', 'Example: leaf fixtures, 11 hooks and 4 idle peers; medians across retained samples.', '', '| Engine | Cold complete install (us total) | Complete remove (us total, warm) | Detour-to-original (ns/call batch average) |', '| --- | ---: | ---: | ---: |']
 for name in ENGINES:
  def value(metric):return next(r['median_ns'] for r in rows if r['engine']==name and r['hooks']==11 and r['peers']==4 and r['callers']==0 and r['metric']==metric)
  lines.append(f'| {name} | {value("complete_install_cold")*11/1000:.2f} | {value("complete_remove_warm")*11/1000:.2f} | {value("detour_original"):.2f} |')
 lines+=['','## Source-form compatibility','', '| Engine | Call behavior verified | API rejected | Creation only | N/A | Failed |','| --- | ---: | ---: | ---: | ---: | ---: |']
 for name in ENGINES:
  counts=collections.Counter(p['status'] for p in manifest['probes'] if p['engine']==name)
  lines.append('| '+name+' | '+' | '.join(str(counts[k]) for k in ['CALL_BEHAVIOR_VERIFIED','API_REJECTED','CREATION_ONLY_NOT_SEMANTICALLY_VALIDATED','NOT_APPLICABLE','FAILED'])+' |')
 lines+=['','## Generated unwind observations','', '| Engine | Registered nonleaf | Relative CALL | RBP frame / CH byte write |','| --- | --- | --- | --- |']
 for name in ENGINES:
  cells=[]
  for case in ['registered_nonleaf','relative_call','frame_byte_ch']:
   item=next(p for p in manifest['probes'] if p['engine']==name and p['case']==case)
   cells.append(item.get('row',{}).get('unwind',item['status']))
  lines.append('| '+name+' | '+' | '.join(cells)+' |')
 lines+=['','## Actual API create/remove observations','', '| Target | Result |','| --- | --- |']
 for name,status in manifest['application_targets']['classifications'].items():lines.append(f'| {name} | {status} |')
 lines+=['','Actual Windows targets were not enabled/executed. API refusals remain deployment gaps.','', 'No equivalent-safety or cross-host ranking is established. See raw data and full per-case/paired-interval statistics.']
 (Path(output)/'REPORT.md').write_text('\n'.join(lines)+'\n');print('\n'.join(lines))
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--build');parser.add_argument('--output');parser.add_argument('--audit');parser.add_argument('--self-test',action='store_true');args=parser.parse_args()
 if args.self_test:check_controls()
 elif args.audit:audit(args.audit)
 else:
  if not args.build or not args.output:parser.error('--build and --output are required')
  measure(args.build,args.output)
