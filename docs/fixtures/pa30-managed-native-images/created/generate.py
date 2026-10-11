"""Create typed PA30/PA31 for original mixed and ReadyToRun images."""
from pathlib import Path
import subprocess,os,hashlib,json
root=Path(__file__).resolve().parent;cli=os.environ.get('WINDOWS_DELTA_CLI','ms-delta');rows=[]
for family in ['readytorun','mixed']:
 for direction in ['forward','reverse']:
  source=root.parent/family/('source.dll' if direction=='forward' else 'target.dll');target=root.parent/family/('target.dll' if direction=='forward' else 'source.dll')
  for fmt in ['pa30','pa31']:
   name=family+'-'+direction+'-'+fmt;s=source.read_bytes();t=target.read_bytes();(root/(name+'.source')).write_bytes(s);(root/(name+'.target')).write_bytes(t);delta=root/(name+'.delta');r=subprocess.run([cli,'create','--format',fmt,'--pe','--source',str(source),'--target',str(target),'--output',str(delta)],text=True,capture_output=True)
   if r.returncode:raise RuntimeError(r.stderr)
   rows.append({'name':name,'family':family,'format':fmt,'direction':direction,'source':name+'.source','target':name+'.target','delta':name+'.delta','delta_size':delta.stat().st_size,'delta_sha256':hashlib.sha256(delta.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(s).hexdigest(),'target_sha256':hashlib.sha256(t).hexdigest()})
(root/'manifest.json').write_text(json.dumps(rows,indent=2)+'\n')
