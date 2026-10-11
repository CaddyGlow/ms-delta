"""Pin original native machine bytes after ilasm's temporary IL wrapper."""
from pathlib import Path
import struct,json,hashlib
root=Path(__file__).resolve().parent
u16=lambda b,o:struct.unpack_from('<H',b,o)[0]
u32=lambda b,o:struct.unpack_from('<I',b,o)[0]
records={}
for name in ['source','target']:
 b=bytearray((root/(name+'-ilasm.dll')).read_bytes());nt=u32(b,60);o=nt+24;sec=o+u16(b,nt+20);sections=[(u32(b,sec+i*40+12),u32(b,sec+i*40+16),u32(b,sec+i*40+20)) for i in range(u16(b,nt+6))]
 def locate(rva):
  return next(raw+rva-va for va,size,raw in sections if va<=rva<va+size)
 cli=locate(u32(b,o+112+14*8));assert u32(b,cli+16)==0;md=locate(u32(b,cli+8));cursor=md+16+((u32(b,md+12)+3)//4*4);count=u16(b,cursor+2);cursor+=4;streams={}
 for _ in range(count):
  end=b.index(0,cursor+8);stream=bytes(b[cursor+8:end]).decode();streams[stream]=md+u32(b,cursor);cursor=(end+4)&~3
 t=streams.get('#~',streams.get('#-'));assert b[t+6]==0;valid=struct.unpack_from('<Q',b,t+8)[0];cursor=t+24;rows=[0]*64
 for i in range(64):
  if valid>>i&1:rows[i]=u32(b,cursor);cursor+=4
 widths=[10,6,14,2,6,2]
 for i,w in enumerate(widths):cursor+=rows[i]*w
 methods=[]
 for i in range(rows[6]):
  p=cursor+i*14;string=streams['#Strings']+u16(b,p+8);end=b.index(0,string);method=bytes(b[string:end]).decode();rva=u32(b,p);raw=locate(rva)
  if method=='NativeOp':
   assert b[raw]&3==2;assert bytes(b[raw+1:raw+6])==(b'\x8b\xc1\x03\xc2\xc3' if name=='source' else b'\x8b\xc1\x2b\xc2\xc3')
   struct.pack_into('<I',b,p,rva+1);struct.pack_into('<H',b,p+4,5);rva+=1;raw+=1
  methods.append({'name':method,'rva':rva,'impl_flags':u16(b,p+4),'bytes':bytes(b[raw:raw+5]).hex()})
 assert any(x['name']=='NativeOp' and x['impl_flags']==5 for x in methods)
 (root/(name+'.dll')).write_bytes(b);records[name]={'size':len(b),'sha256':hashlib.sha256(b).hexdigest(),'clr_flags':u32(b,cli+16),'methods':methods}
(root/'inputs.json').write_text(json.dumps(records,indent=2)+'\n')
