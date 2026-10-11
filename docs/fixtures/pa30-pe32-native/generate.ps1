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


$ErrorActionPreference='Stop';$root='C:\pa30-pe32-oracle';$rows=@();foreach($family in @('basic','rich','signatures','attributes','wide')){foreach($platform in @('anycpu','x86','x64')){$source=[IO.File]::ReadAllBytes("$root\$family\$platform\source\fixture.dll");$target=[IO.File]::ReadAllBytes("$root\$family\$platform\target\fixture.dll");foreach($graph in @('legacy','cli4')){if($platform-eq'x64'-and$graph-eq'cli4'){continue};[long]$types=15;[long]$mask=57854;[long]$expected=2;$flags=@(0,16384,32768,49152,-1);if($platform-eq'x64'){$mask=58942;$expected=8};if($graph-eq'cli4'){$types=245;$mask=($mask-band(-bnot49152))-bor6291456;$expected=16;$flags=@(0,2097152,4194304,6291456,-1)}
foreach($direction in @('forward','reverse')){foreach($f in $flags){$s=$source;$t=$target;if($direction-eq'reverse'){$s=$target;$t=$source};$name="$direction-$f";[long]$set=$f;[long]$reset=$mask-band(-bnot$f);if($f-eq-1){$set=0;$reset=0;$name="$direction-default"};$folder="$root\$family\$platform\$graph";New-Item -ItemType Directory -Force $folder|Out-Null
try{$d=[Oracle]::CreateFlags($s,$t,32771,$types,$set,$reset);$a=[Oracle]::Apply($s,$d);if([Convert]::ToBase64String($a)-ne[Convert]::ToBase64String($t)){throw 'native target mismatch'};$h=[Oracle]::Info($d);if($h.Type-ne$expected){throw "native selected wrong graph $($h.Type) expected $expected"};[IO.File]::WriteAllBytes("$folder\$name.delta",$d);$rows+=@{family=$family;platform=$platform;graph=$graph;direction=$direction;name=$name;path="$family/$platform/$graph/$name.delta";set_flags=$set;reset_flags=$reset;success=$true;native_roundtrip=$true;delta_size=$d.Length;file_type_set=$h.TypeSet;file_type=$h.Type;flags=$h.Flags;target_size=$h.TargetSize.ToUInt64();hash_alg=$h.Alg}}
catch{$rows+=@{family=$family;platform=$platform;graph=$graph;direction=$direction;name=$name;set_flags=$set;reset_flags=$reset;success=$false;error=$_.Exception.Message}}
}}}}};$rows|ConvertTo-Json -Depth 5|Set-Content -Encoding UTF8 "$root\manifest.json";@{calls=$rows.Count;success=@($rows|Where-Object{$_.success}).Count;failure=@($rows|Where-Object{!$_.success}).Count}|ConvertTo-Json
