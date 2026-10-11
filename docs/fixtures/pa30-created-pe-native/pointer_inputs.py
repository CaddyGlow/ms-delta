"""Original, never-executed PE images with 2,048 base relocation pointers."""
from pathlib import Path
import struct, hashlib, json
root=Path(__file__).resolve().parent
p16=lambda b,o,v:struct.pack_into('<H',b,o,v)
p32=lambda b,o,v:struct.pack_into('<I',b,o,v)
p64=lambda b,o,v:struct.pack_into('<Q',b,o,v)
for bits in (32,64):
 width=bits//8; ptr_size=2048*width; ptr_rva=0x2000; reloc_rva=ptr_rva+ptr_size
 entries=[]
 for page in range(ptr_size//4096):
  offsets=[(3 if bits==32 else 10)<<12|i for i in range(0,4096,width)]
  entries.append(struct.pack('<II',ptr_rva+page*4096,8+len(offsets)*2)+struct.pack('<'+'H'*len(offsets),*offsets))
 relocs=b''.join(entries); reloc_raw=(len(relocs)+511)//512*512
 folder=root/('i386-pointers' if bits==32 else 'amd64-pointers');folder.mkdir(exist_ok=True)
 for direction,base in [('source',0x400000 if bits==32 else 0x140000000),('target',0x530000 if bits==32 else 0x183000000)]:
  opt_size=224 if bits==32 else 240; b=bytearray(512+4096+ptr_size+reloc_raw)
  b[:2]=b'MZ';p32(b,0x3c,0x80);b[0x80:0x84]=b'PE\0\0';nt=0x84
  p16(b,nt,0x14c if bits==32 else 0x8664);p16(b,nt+2,3);p16(b,nt+16,opt_size);p16(b,nt+18,0x102 if bits==32 else 0x22)
  o=nt+20;p16(b,o,0x10b if bits==32 else 0x20b);p32(b,o+4,4096);p32(b,o+8,ptr_size+reloc_raw);p32(b,o+16,0x1000);p32(b,o+20,0x1000)
  if bits==32:p32(b,o+24,ptr_rva);p32(b,o+28,base)
  else:p64(b,o+24,base)
  p32(b,o+32,4096);p32(b,o+36,512);p16(b,o+40,6);p16(b,o+48,6);p32(b,o+56,reloc_rva+((len(relocs)+4095)//4096*4096));p32(b,o+60,512);p16(b,o+68,3)
  p32(b,o+(92 if bits==32 else 108),16);dd=o+(96 if bits==32 else 112);p32(b,dd+40,reloc_rva);p32(b,dd+44,len(relocs))
  for i,(name,va,sz,rawsz,raw,flags) in enumerate([(b'.text',0x1000,4096,4096,512,0x60000020),(b'.ptrs',ptr_rva,ptr_size,ptr_size,4608,0x40000040),(b'.reloc',reloc_rva,len(relocs),reloc_raw,4608+ptr_size,0x42000040)]):
   sec=o+opt_size+i*40;b[sec:sec+len(name)]=name
   for off,val in [(8,sz),(12,va),(16,rawsz),(20,raw),(36,flags)]:p32(b,sec+off,val)
  x=5071
  for i in range(4096):
   x^=(x<<13)&0xffffffff;x^=x>>17;x^=(x<<5)&0xffffffff;b[512+i]=x&255
  for i in range(2048):
   x^=(x<<13)&0xffffffff;x^=x>>17;x^=(x<<5)&0xffffffff
   (p32 if bits==32 else p64)(b,4608+i*width,base+0x1000+(x%4096))
  b[4608+ptr_size:4608+ptr_size+len(relocs)]=relocs
  (folder/(direction+'.exe')).write_bytes(b)
rows=[]
for folder in sorted(root.iterdir()):
 if folder.is_dir() and (folder/'source.exe').exists():rows.append({'pair':folder.name,'files':{n:{'size':(folder/n).stat().st_size,'sha256':hashlib.sha256((folder/n).read_bytes()).hexdigest()} for n in ['source.exe','target.exe']}})
(root/'inputs.json').write_text(json.dumps(rows,indent=2)+'\n')
