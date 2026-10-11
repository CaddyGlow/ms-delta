"""Copy existing original managed PE inputs and derive header-only controls."""
from pathlib import Path
import struct,json,hashlib
root=Path(__file__).resolve().parent;prior=root.parent/'pa30-pe32-native'
for family in ['basic','rich','signatures','attributes','wide']:
 for platform in ['anycpu','x86','x64']:
  folder=root/family/platform;folder.mkdir(parents=True,exist_ok=True)
  for name in ['source.dll','target.dll']:(folder/name).write_bytes((prior/family/platform/name).read_bytes())
for platform in ['anycpu','x86','x64']:
 folder=root/'header'/platform;folder.mkdir(parents=True,exist_ok=True)
 original=(prior/'basic'/platform/'source.dll').read_bytes();nt=struct.unpack_from('<I',original,0x3c)[0]
 for name,stamp,checksum in [('source.dll',0x12345678,0x89abcdef),('target.dll',0xfedcba98,0)]:
  b=bytearray(original);struct.pack_into('<I',b,nt+8,stamp);struct.pack_into('<I',b,nt+24+64,checksum);(folder/name).write_bytes(b)
rows=[]
for family in ['basic','rich','signatures','attributes','wide','header']:
 for platform in ['anycpu','x86','x64']:
  folder=root/family/platform;rows.append({'pair':family+'/'+platform,'family':family,'platform':platform,'files':{n:{'size':(folder/n).stat().st_size,'sha256':hashlib.sha256((folder/n).read_bytes()).hexdigest()} for n in ['source.dll','target.dll']}})
(root/'inputs.json').write_text(json.dumps(rows,indent=2)+'\n')
