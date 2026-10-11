"""Original inputs intended to exercise adaptive native Huffman tables."""
from pathlib import Path
import json,hashlib
root=Path(__file__).resolve().parent
x=5071;random=bytearray()
for _ in range(65536):
 x^=(x<<13)&0xffffffff;x^=x>>17;x^=(x<<5)&0xffffffff;random.append(x&255)
rows=[]
for size in [4096,8192]:
 name='repeat-'+str(size);target=bytearray(random);target[32768:32768+size]=random[4096:4096+size];(root/(name+'.source')).write_bytes(b'');(root/(name+'.target')).write_bytes(target);rows.append({'name':name,'source_sha256':hashlib.sha256(b'').hexdigest(),'target_sha256':hashlib.sha256(target).hexdigest(),'source_size':0,'target_size':len(target)})
(root/'inputs.json').write_text(json.dumps(rows,indent=2)+'\n')
