"""Original deterministic native PA31 oracle inputs."""
from pathlib import Path
import json,hashlib
root=Path(__file__).resolve().parent
def random(size):
 x=5071;b=bytearray()
 for _ in range(size):
  x^=(x<<13)&0xffffffff;x^=x>>17;x^=(x<<5)&0xffffffff;b.append(x&255)
 return bytes(b)
s=random(8192);changed=bytearray(s);changed[113:150]=b'Native PA31 original mutation vector!'
cases=[('empty',b'',b''),('abc',b'',b'abc'),('all256',b'',bytes(range(256))),('random',b'',s),('repetitive',b'',b'Original native PA31 repeated vector\n'*256),('identical',s,s),('changed',s,bytes(changed)),('reverse',bytes(changed),s)]
rows=[]
for name,source,target in cases:
 (root/(name+'.source')).write_bytes(source);(root/(name+'.target')).write_bytes(target);rows.append({'name':name,'source_sha256':hashlib.sha256(source).hexdigest(),'target_sha256':hashlib.sha256(target).hexdigest(),'source_size':len(source),'target_size':len(target)})
(root/'inputs.json').write_text(json.dumps(rows,indent=2)+'\n')
