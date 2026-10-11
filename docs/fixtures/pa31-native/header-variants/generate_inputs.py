"""Re-envelope original native PA31 data with controlled header mutations."""
from pathlib import Path
import json
root=Path(__file__).resolve().parent
class Reader:
 def __init__(self,b):self.b=b;self.p=3
 def bits(self,n):
  v=sum((self.b[(self.p+i)//8]>>((self.p+i)%8)&1)<<i for i in range(n));self.p+=n;return v
 def number(self):
  n=1
  while not self.bits(1):n+=1
  return self.bits(n*4)
 def buffer(self):
  n=self.number();self.p=(self.p+7)&~7;s=self.p//8;self.p+=n*8;return self.b[s:s+n]
class Writer:
 def __init__(self):self.b=bytearray([0]);self.p=3
 def bits(self,v,n):
  for i in range(n):
   if self.p//8==len(self.b):self.b.append(0)
   self.b[self.p//8]|=((v>>i)&1)<<(self.p%8);self.p+=1
 def number(self,v):
  n=max(1,(v.bit_length()+3)//4);self.bits(0,n-1);self.bits(1,1);self.bits(v,n*4)
 def buffer(self,b):
  self.number(len(b))
  while self.p%8:self.bits(0,1)
  for c in b:self.bits(c,8)
 def finish(self):self.b[0]|=(-self.p)%8;return bytes(self.b)
base=(root.parent/'identical-268435456.delta').read_bytes();o=Reader(base[12:]);h=Reader(o.buffer());values=[h.number() for _ in range(5)];digest=h.buffer();fields=[h.number() for _ in range(3)];sourcehash=h.buffer();pre=o.buffer();patch=o.buffer();rows=[]
for triple in [(136,1,0),(136,1,1),(136,1,2),(136,2,0),(80,0,0)]:
 name='fields-'+'-'.join(map(str,triple));w=Writer()
 for v in values:w.number(v)
 w.buffer(digest)
 for v in triple:w.number(v)
 w.buffer(sourcehash);out=Writer();out.buffer(w.finish());out.buffer(pre);out.buffer(patch);d=base[:12]+out.finish();(root/(name+'.delta')).write_bytes(d);rows.append({'name':name,'fields':triple,'delta':name+'.delta','source':'../identical.source','target':'../identical.target'})
assert (root/'fields-136-1-0.delta').read_bytes()==base
(root/'manifest.json').write_text(json.dumps(rows,indent=2)+'\n')
