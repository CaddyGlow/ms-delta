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
 [DllImport("msdelta.dll",SetLastError=true)]static extern bool CreateDeltaB(long type,long set,long reset,Input source,Input target,Input so,Input to,Input go,ref long time,uint alg,out Output result);
 [DllImport("msdelta.dll",SetLastError=true)]static extern bool ApplyDeltaB(long flags,Input source,Input delta,out Output result);
 [DllImport("msdelta.dll",SetLastError=true)]static extern bool GetDeltaInfoB(Input delta,out Header header);
 [DllImport("msdelta.dll")]static extern bool DeltaFree(IntPtr ptr);
 static Input Pin(byte[] a,out GCHandle pin){if(a.Length==0){pin=default(GCHandle);return new Input();}pin=GCHandle.Alloc(a,GCHandleType.Pinned);return new Input{Data=pin.AddrOfPinnedObject(),Size=(UIntPtr)a.Length};}
 static void Free(GCHandle h){if(h.IsAllocated)h.Free();}
 static byte[] Take(Output o){try{byte[] b=new byte[(int)o.Size.ToUInt64()];Marshal.Copy(o.Data,b,0,b.Length);return b;}finally{DeltaFree(o.Data);}}
 public static byte[] RandomData(int size){byte[] b=new byte[size];uint x=5071;for(int i=0;i<size;i++){x^=x<<13;x^=x>>17;x^=x<<5;b[i]=(byte)x;}return b;}
 public static byte[] CreateFlags(byte[] s,byte[] t,uint alg,long types,long set,long reset){GCHandle sp,tp;Input si=Pin(s,out sp),ti=Pin(t,out tp);try{Output o;long time=132537600000000000;if(!CreateDeltaB(types,set,reset,si,ti,new Input(),new Input(),new Input(),ref time,alg,out o))throw new Exception("CreateDeltaB:"+Marshal.GetLastWin32Error());return Take(o);}finally{Free(sp);Free(tp);}}
 public static byte[] Apply(byte[] s,byte[] d){GCHandle sp,dp;Input si=Pin(s,out sp),di=Pin(d,out dp);try{Output o;if(!ApplyDeltaB(0,si,di,out o))throw new Exception("ApplyDeltaB:"+Marshal.GetLastWin32Error());return Take(o);}finally{Free(sp);Free(dp);}}
 public static Header Info(byte[] d){GCHandle dp;Input di=Pin(d,out dp);try{Header h;if(!GetDeltaInfoB(di,out h))throw new Exception("GetDeltaInfoB:"+Marshal.GetLastWin32Error());return h;}finally{Free(dp);}}
}
'@


$ErrorActionPreference='Stop';$root='C:\pa30-cli-rich';$source=[IO.File]::ReadAllBytes("$root\source\fixture.dll");$target=[IO.File]::ReadAllBytes("$root\target\fixture.dll")
$flags=@(0,2097152,4194304,6291456);$rows=@();foreach($basis in @('empty','managed')){foreach($f in $flags){$name="$basis-$f";[byte[]]$s=@();if($basis-eq'managed'){$s=$source};[long]$reset=6694462 -band (-bnot $f)
 try{$d=[Oracle]::CreateFlags($s,$target,32771,245,$f,$reset);$a=[Oracle]::Apply($s,$d);if([Convert]::ToBase64String($a)-ne[Convert]::ToBase64String($target)){throw 'oracle mismatch'};[IO.File]::WriteAllBytes("$root\$name.delta",$d);$h=[Oracle]::Info($d);$rows+=@{name=$name;basis=$basis;requested_type_set=245;set_flags=$f;reset_flags=$reset;success=$true;native_roundtrip=$true;delta_size=$d.Length;file_type_set=$h.TypeSet;file_type=$h.Type;flags=$h.Flags;target_size=$h.TargetSize.ToUInt64();hash_alg=$h.Alg}}
 catch{$rows+=@{name=$name;basis=$basis;set_flags=$f;reset_flags=$reset;success=$false;error=$_.Exception.Message}}
}}
$rows|ConvertTo-Json -Depth 5|Set-Content -Encoding UTF8 "$root\manifest.json";$rows|ConvertTo-Json -Depth 5
