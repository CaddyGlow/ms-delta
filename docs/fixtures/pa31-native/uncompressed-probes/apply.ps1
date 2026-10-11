$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
public static class Oracle {
 [StructLayout(LayoutKind.Sequential)] public struct Input {public IntPtr Data;public UIntPtr Size;public int Editable;}
 [StructLayout(LayoutKind.Sequential)] public struct Output {public IntPtr Data;public UIntPtr Size;}
 [StructLayout(LayoutKind.Sequential)] public struct Hash {public uint Size;[MarshalAs(UnmanagedType.ByValArray,SizeConst=32)]public byte[] Value;}
 [StructLayout(LayoutKind.Sequential)] public struct Header {public long TypeSet,Type,Flags;public UIntPtr TargetSize;public long FileTime;public uint Alg;public Hash Hash;}
 [DllImport(@"C:\pa31-oracle\UpdateCompression.dll",SetLastError=true)]static extern bool CreateDeltaB(long type,long set,long reset,Input source,Input target,Input so,Input to,Input go,ref long time,uint alg,out Output result);
 [DllImport(@"C:\pa31-oracle\UpdateCompression.dll",SetLastError=true)]static extern bool ApplyDeltaB(long flags,Input source,Input delta,out Output result);
 [DllImport(@"C:\pa31-oracle\UpdateCompression.dll",SetLastError=true)]static extern bool GetDeltaInfoB(Input delta,out Header header);
 [DllImport(@"C:\pa31-oracle\UpdateCompression.dll")]static extern bool DeltaFree(IntPtr ptr);
 static Input Pin(byte[] a,out GCHandle pin){if(a.Length==0){pin=default(GCHandle);return new Input();}pin=GCHandle.Alloc(a,GCHandleType.Pinned);return new Input{Data=pin.AddrOfPinnedObject(),Size=(UIntPtr)a.Length};}
 static void Free(GCHandle h){if(h.IsAllocated)h.Free();}
 static byte[] Take(Output o){try{byte[] b=new byte[(int)o.Size.ToUInt64()];if(b.Length!=0)Marshal.Copy(o.Data,b,0,b.Length);return b;}finally{DeltaFree(o.Data);}}
 public static byte[] RandomData(int size){byte[] b=new byte[size];uint x=5071;for(int i=0;i<size;i++){x^=x<<13;x^=x>>17;x^=x<<5;b[i]=(byte)x;}return b;}
 public static byte[] CreateFlags(byte[] s,byte[] t,uint alg,long types,long set,long reset){GCHandle sp,tp;Input si=Pin(s,out sp),ti=Pin(t,out tp);try{Output o;long time=132537600000000000;if(!CreateDeltaB(types,set,reset,si,ti,new Input(),new Input(),new Input(),ref time,alg,out o))throw new Exception("CreateDeltaB:"+Marshal.GetLastWin32Error());return Take(o);}finally{Free(sp);Free(tp);}}
 public static byte[] Apply(byte[] s,byte[] d){GCHandle sp,dp;Input si=Pin(s,out sp),di=Pin(d,out dp);try{Output o;if(!ApplyDeltaB(0,si,di,out o))throw new Exception("ApplyDeltaB:"+Marshal.GetLastWin32Error());return Take(o);}finally{Free(sp);Free(dp);}}
 public static Header Info(byte[] d){GCHandle dp;Input di=Pin(d,out dp);try{Header h;if(!GetDeltaInfoB(di,out h))throw new Exception("GetDeltaInfoB:"+Marshal.GetLastWin32Error());return h;}finally{Free(dp);}}
}
'@





$root='C:\pa31-oracle';$rows=@();foreach($name in @('uncompressed-empty','uncompressed-abc','uncompressed-identical','uncompressed-changed','uncompressed-reverse')){$d=[IO.File]::ReadAllBytes("$root\$name.delta");$row=@{name=$name};try{$h=[Oracle]::Info($d);$row.info_success=$true;$row.file_type_set=$h.TypeSet;$row.flags=$h.Flags}catch{$row.info_success=$false;$row.info_error=$_.Exception.Message};try{$s=[IO.File]::ReadAllBytes("$root\$name.source");$t=[IO.File]::ReadAllBytes("$root\$name.target");$a=[Oracle]::Apply($s,$d);$row.apply_success=$true;$row.target_matches=([Convert]::ToBase64String($a)-eq[Convert]::ToBase64String($t))}catch{$row.apply_success=$false;$row.apply_error=$_.Exception.Message};$rows+=$row};$rows|ConvertTo-Json|Set-Content -Encoding UTF8 "$root\uncompressed-results.json";$rows|ConvertTo-Json
