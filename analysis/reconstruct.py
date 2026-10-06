"""Read-only offline reconstruction of Research2_mitacs.zip; no cloud calls.
Usage: python reconstruct.py /path/Research2_mitacs.zip /path/output
"""
import zipfile,io,json,hashlib,csv,sys,collections
from pathlib import Path
from datetime import datetime
src=Path(sys.argv[1]);out=Path(sys.argv[2]);out.mkdir(parents=True,exist_ok=True)
def sha(b):return hashlib.sha256(b).hexdigest()
def t(s):return datetime.fromisoformat(s.replace('Z','+00:00')).timestamp()
def csvwrite(name,rows):
 if not rows:return
 keys=list(dict.fromkeys(k for r in rows for k in r))
 with (out/name).open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=keys);w.writeheader();w.writerows(rows)
def dump(name,v):(out/name).write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
files=[];archives=[];runs=[];scenarios=[];obsrows=[];trans=[];ctrows=[];allct=set();dupes=[];events=[];coverage=[];states=collections.Counter();seen=set()
with zipfile.ZipFile(src) as outer:
 for n in outer.namelist():
  if n.endswith('/') or n.startswith('__MACOSX/') or '/.DS_Store' in n:continue
  b=outer.read(n);files.append({'path':n,'bytes':len(b),'sha256':sha(b)})
  if not n.endswith('.zip'):continue
  with zipfile.ZipFile(io.BytesIO(b)) as z:
   archives.append({'path':n,'sha256':sha(b),'zip_comment':z.comment.decode(errors='replace'),'entries':len(z.namelist())})
   if 'live_run_evidence.json' not in z.namelist():continue
   raw=z.read('live_run_evidence.json');d=json.loads(raw);rid=d['run_id'];prov=d['provenance'];co=prov['git_commit'];final='/final runs/' in n
   assert rid not in seen;seen.add(rid)
   for x in z.namelist():
    if x.startswith('live_run_sha'):dupes.append({'archive':n,'copy':x,'byte_identical':z.read(x)==raw})
   runs.append({'run_id':rid,'github_run_id':prov['github_run_id'],'commit':co,'corpus':'final' if final else 'historical','archive':n,'started_at':d['run_started_at'],'ended_at':d['run_ended_at'],'elapsed_s':d['monotonic_elapsed_seconds'],'recorded_status':d['status'],'clock_skew_s':d.get('clock_sanity',{}).get('skew_seconds'),'clock_status':d.get('clock_sanity',{}).get('status'),'evidence_sha256':sha(raw),'source_available':co.startswith(('1366e30','9e704e4'))})
   for sid,s in d.get('scenarios',{}).items():
    base={'run_id':rid,'github_run_id':prov['github_run_id'],'commit':co[:7],'corpus':'final' if final else 'historical','scenario':sid}
    scenarios.append({**base,'started_at':s['started_at'],'ended_at':s['ended_at'],'elapsed_s':s['elapsed_seconds'],'recorded_status':s['status'],'error':s.get('error',''),'archive':n,'pointer':f'/scenarios/{sid}'})
    for section in ['events','restoration']:
     for i,e in enumerate(s.get(section,[])):
      pointer=f'/scenarios/{sid}/{section}/{i}'
      # Retain non-CloudTrail scenario records verbatim; identifiers stay researcher-held.
      events.append({**base,'pointer':pointer,'record':e})
      if 'observations' not in e or not e['observations'] or 't' not in e['observations'][0]:continue
      oo=e['observations'];expected=('denied' if e['kind'] in {'revoke_propagation','new_session_block_propagation','phase1_removal_propagation','exception_strict_restoration_propagation'} else 'allowed');old='allowed' if expected=='denied' else 'denied';last_old=None;first_new=None;third=None;streak=0
      for j,o in enumerate(oo):
       states[o['state']]+=1
       obsrows.append({**base,'kind':e['kind'],'section':section,'index':j,'t':o['t'],'state':o['state'],'pointer':pointer+f'/observations/{j}'})
       if o['state']==old:last_old=o['t'];streak=0;first_new=None
       elif o['state']==expected:
        if streak==0:first_new=o['t']
        streak+=1
        if streak==3:third=o['t']
       else:streak=0
      in_count=sum(o['state']==expected and o['t']<=300 for o in oo)
      clock='completion' if co.startswith('9e704e4') else ('probe_start' if co.startswith('1366e30') else 'unverified_revision')
      # Recorded-offset criterion, not retroactive assurance of source semantics.
      verdict='THREE_EXPECTED_RECORDED_WITHIN_WINDOW' if third is not None and third<=300 else ('EXPECTED_RECORDED_UNCONFIRMED' if in_count else 'NO_EXPECTED_RECORDED_WITHIN_WINDOW')
      # A stable result may count unexpected error states; never promote these.
      unusual=sorted({str(o['state']) for o in oo if o['state'] not in ['allowed','denied']})
      trans.append({**base,'kind':e['kind'],'section':section,'observations':len(oo),'initial_recorded_state':oo[0]['state'],'expected_old_state':old,'expected_opposite_state':expected,'last_old_s':last_old,'first_new_s':first_new,'third_new_s':third,'in_window_expected':in_count,'unexpected_states':json.dumps(unusual),'raw_status':e.get('status'),'raw_first_new_s':e.get('first_new_observation_t'),'raw_stable_s':e.get('stable_observation_t'),'recorded_offset_verdict':verdict,'clock_semantics':clock,'pointer':pointer})
    ct=s.get('cloudtrail',{});rawct=ct.get('raw_redacted',[]);ids={e['eventID'] for e in rawct if 'eventID' in e};allct|=ids
    ctrows.append({**base,'candidate_count':ct.get('correlation',{}).get('candidate_count'),'normalized_count':len(ct.get('normalized',[])),'raw_count':len(rawct),'unique_event_ids':len(ids),'correlation_status':ct.get('correlation',{}).get('status'),'collected_at':ct.get('collected_at'),'window_start':ct.get('window_start'),'window_end':ct.get('window_end'),'collection_before_window_end':t(ct['collected_at'])<t(ct['window_end']) if ct.get('collected_at') and ct.get('window_end') else None})
    for interval in [60,300,900,1800,3600]:coverage.append({**base,'interval_s':interval,'duration_s':s['elapsed_seconds'],'required_s':4*interval,'duration_gate_only':s['elapsed_seconds']>=4*interval,'validated_baseline_comparison_available':False})
runs.sort(key=lambda r:r['started_at']);scenarios.sort(key=lambda r:r['started_at']);trans.sort(key=lambda r:(r['github_run_id'],r['scenario'],r['pointer']))
for name,rows in [('inventory.csv',files),('archives.csv',archives),('runs.csv',runs),('scenarios.csv',scenarios),('transitions.csv',trans),('observations.csv',obsrows),('cloudtrail.csv',ctrows),('coverage.csv',coverage),('duplicate_evidence.csv',dupes)]:csvwrite(name,rows)
# Do not include original account identifiers in derived deliverable event extracts.
def sanitize(v):
 if isinstance(v,dict):return {k:sanitize(x) for k,x in v.items()}
 if isinstance(v,list):return [sanitize(x) for x in v]
 if isinstance(v,str):
  import re
  return re.sub(r'(?<=:)\d{12}(?=:)', '<ACCOUNT>',v)
 return v
dump('scenario_records.json',sanitize(events))
summary={'input_sha256':sha(src.read_bytes()),'retained_files_excluding_os_metadata':len(files),'distinct_live_evidence_runs':len(runs),'distinct_github_runs':len({r['github_run_id'] for r in runs}),'scenario_attempts':len(scenarios),'status_counts':dict(collections.Counter(s['recorded_status'] for s in scenarios)),'per_scenario':{sid:dict(collections.Counter(s['recorded_status'] for s in scenarios if s['scenario']==sid)) for sid in sorted({s['scenario'] for s in scenarios})},'propagation_observations':len(obsrows),'propagation_states':dict(states),'cloudtrail_raw_rows':sum(r['raw_count'] for r in ctrows),'unique_cloudtrail_event_ids':len(allct),'missing_source_commits':sorted({r['commit'] for r in runs if not r['source_available']}),'comparative_live_metrics':'NOT_ESTABLISHED'}
dump('summary.json',summary);print(json.dumps(summary,indent=2))
