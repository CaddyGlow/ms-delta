"""Rust-created PA31 original RAW and typed PE controls."""
from pathlib import Path
import json,hashlib,os,subprocess
root=Path(__file__).resolve().parent;prior=root.parent;cli=os.environ.get('WINDOWS_DELTA_CLI','ms-delta');cases=[]
for row in json.loads((prior/'pa31-native/inputs.json').read_text()):
 name=row['name'];cases.append((name,prior/'pa31-native'/(name+'.source'),prior/'pa31-native'/(name+'.target'),False))
for pair in ['i386-pointers','amd64-pointers']:
 folder=prior/'pa30-created-pe-native'/pair
 for direction in ['forward','reverse']:cases.append((pair+'-'+direction,folder/('source.exe' if direction=='forward' else 'target.exe'),folder/('target.exe' if direction=='forward' else 'source.exe'),True))
for platform in ['anycpu','x86','x64']:
 folder=prior/'pa30-created-cli-native/signatures'/platform
 for direction in ['forward','reverse']:cases.append(('managed-'+platform+'-'+direction,folder/('source.dll' if direction=='forward' else 'target.dll'),folder/('target.dll' if direction=='forward' else 'source.dll'),True))
rows=[]
for name,source,target,pe in cases:
 s=source.read_bytes();t=target.read_bytes();(root/(name+'.source')).write_bytes(s);(root/(name+'.target')).write_bytes(t);delta=root/(name+'.delta')
 args=[cli,'create','--format','pa31','--source',str(root/(name+'.source')),'--target',str(root/(name+'.target')),'--output',str(delta)]
 if pe:args+=['--pe']
 r=subprocess.run(args,text=True,capture_output=True)
 if r.returncode:raise RuntimeError(r.stderr)
 rows.append({'name':name,'pe':pe,'source':name+'.source','target':name+'.target','delta':name+'.delta','source_sha256':hashlib.sha256(s).hexdigest(),'target_sha256':hashlib.sha256(t).hexdigest(),'delta_sha256':hashlib.sha256(delta.read_bytes()).hexdigest(),'delta_size':delta.stat().st_size,'source_size':len(s),'target_size':len(t)})
(root/'manifest.json').write_text(json.dumps(rows,indent=2)+'\n');print('Created',len(rows),'PA31 cases')
