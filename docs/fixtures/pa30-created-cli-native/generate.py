"""Create typed and RAW PA30 controls with the standalone Rust CLI."""
from pathlib import Path
import json, subprocess, os, hashlib, importlib.util
root=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('buffers',root.parent/'pa30-pe-native/inspect_buffers.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
cli=os.environ.get('WINDOWS_DELTA_CLI','ms-delta');rows=[]
for inp in json.loads((root/'inputs.json').read_text()):
 folder=root/inp['pair']
 for direction in ['forward','reverse']:
  source=folder/('source.dll' if direction=='forward' else 'target.dll');target=folder/('target.dll' if direction=='forward' else 'source.dll')
  for mode in ['pe','raw']:
   delta=folder/(direction+'-'+mode+'.delta')
   args=[cli,'create','--format','pa30','--source',str(source),'--target',str(target),'--output',str(delta)]
   if mode=='pe':args+=['--pe']
   result=subprocess.run(args,text=True,capture_output=True)
   if result.returncode:raise RuntimeError(result.stderr)
  delta=folder/(direction+'-pe.delta');raw=folder/(direction+'-raw.delta')
  rows.append({'name':inp['pair'].replace('/','-')+'-'+direction,'pair':inp['pair'],'family':inp['family'],'platform':inp['platform'],'direction':direction,'source':str(source.relative_to(root)),'target':str(target.relative_to(root)),'delta':str(delta.relative_to(root)),'raw_delta':str(raw.relative_to(root)),'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'target_sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'delta_size':delta.stat().st_size,'raw_delta_size':raw.stat().st_size,'saved_bytes':raw.stat().st_size-delta.stat().st_size,'buffers':m.inspect(delta)})
(root/'manifest.json').write_text(json.dumps(rows,indent=2)+'\n')
print(json.dumps([{k:r[k] for k in ['name','delta_size','raw_delta_size','saved_bytes']} for r in rows],indent=2))
