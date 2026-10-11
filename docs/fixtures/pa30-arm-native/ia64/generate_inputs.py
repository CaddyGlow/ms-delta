"""Original parser-only IA64 PE64 bundles, pdata and pointer relocations."""
from pathlib import Path
import struct,json,hashlib
root=Path(__file__).resolve().parent
p16=lambda b,o,v:struct.pack_into('<H',b,o,v)
p32=lambda b,o,v:struct.pack_into('<I',b,o,v)
p64=lambda b,o,v:struct.pack_into('<Q',b,o,v)
rows=[]
for direction,base,shift in [('source',0x140000000,0),('target',0x183000000,0x1000)]:
 data_rva=0x2000+shift;pdata_rva=0x3000+shift;reloc_rva=0x4000+shift;b=bytearray(1024+4*512);b[:2]=b'MZ';p32(b,60,0x80);b[0x80:0x84]=b'PE\0\0';nt=0x84;p16(b,nt,0x200);p16(b,nt+2,4);p16(b,nt+16,240);p16(b,nt+18,0x22);o=nt+20;p16(b,o,0x20b);p32(b,o+4,512);p32(b,o+8,1536);p32(b,o+16,0x1000);p32(b,o+20,0x1000);p64(b,o+24,base);p32(b,o+32,4096);p32(b,o+36,512);p16(b,o+40,6);p16(b,o+48,6);p32(b,o+56,reloc_rva+4096);p32(b,o+60,1024);p16(b,o+68,3);p32(b,o+108,16);dd=o+112
 for index,rva,size in [(3,pdata_rva,24),(5,reloc_rva,12),(8,data_rva+256,0)]:p32(b,dd+index*8,rva);p32(b,dd+index*8+4,size)
 for i,(name,rva,raw,flags) in enumerate([(b'.text',0x1000,1024,0x60000020),(b'.data',data_rva,1536,0xc0000040),(b'.pdata',pdata_rva,2048,0x40000040),(b'.reloc',reloc_rva,2560,0x42000040)]):
  sec=o+240+i*40;b[sec:sec+len(name)]=name
  for off,val in [(8,512),(12,rva),(16,512),(20,raw),(36,flags)]:p32(b,sec+off,val)
 def bundle(template,slots):return (template|sum(slot<<(5+i*41) for i,slot in enumerate(slots))).to_bytes(16,'little')
 revision=1 if direction=='source' else 2
 b[1024:1040]=bundle(0,[(9<<37)|(1<<20)|(revision<<13)]*3)
 b[1040:1056]=bundle(16,[0,0,(4<<37)|((0x102+shift//16)<<13)])
 b[1056:1072]=bundle(4,[0,0,(12<<37)|(revision<<13)])
 for i in range(16):p64(b,1536+i*8,base+data_rva+128+i*8)
 for i in range(2):struct.pack_into('<III',b,2048+i*12,0x1000+i*32,0x1020+i*32,data_rva+128+i*8)
 struct.pack_into('<IIHH',b,2560,data_rva,12,0xa000,0)
 (root/(direction+'.exe')).write_bytes(b);rows.append({'name':direction,'size':len(b),'sha256':hashlib.sha256(b).hexdigest(),'machine':512,'image_base':base,'global_pointer':data_rva+256,'data_rva':data_rva,'pdata_rva':pdata_rva,'reloc_rva':reloc_rva})
(root/'inputs.json').write_text(json.dumps(rows,indent=2)+'\n')
