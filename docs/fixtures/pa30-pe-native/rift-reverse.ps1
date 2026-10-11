$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ReverseOracle {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr LoadLibraryW(string path);
 [UnmanagedFunctionPointer(CallingConvention.Winapi)]delegate IntPtr Reverse(IntPtr self,long start);
 public static long[][] Run(long[] coordinates,long start){
  IntPtr module=LoadLibraryW(@"C:\Windows\System32\msdelta.dll");if(module==IntPtr.Zero)throw new Exception("LoadLibrary:"+Marshal.GetLastWin32Error());
  IntPtr pairs=Marshal.AllocHGlobal(coordinates.Length*8),obj=Marshal.AllocHGlobal(48);for(int i=0;i<48;i++)Marshal.WriteByte(obj,i,0);
  for(int i=0;i<coordinates.Length;i++)Marshal.WriteInt64(pairs,i*8,coordinates[i]);
  Marshal.WriteIntPtr(obj,IntPtr.Add(module,0x5a078));Marshal.WriteByte(obj,8,1);Marshal.WriteInt32(obj,12,10);Marshal.WriteInt64(obj,16,coordinates.Length/2);Marshal.WriteInt64(obj,24,coordinates.Length/2);Marshal.WriteIntPtr(obj,32,pairs);Marshal.WriteByte(obj,40,1);
  Reverse fn=(Reverse)Marshal.GetDelegateForFunctionPointer(IntPtr.Add(module,0x4060),typeof(Reverse));IntPtr result=fn(obj,start);if(result==IntPtr.Zero)throw new Exception("Reverse returned null");
  long count=Marshal.ReadInt64(result,16);IntPtr entries=Marshal.ReadIntPtr(result,32);if(count<0||count>1000)throw new Exception("unbounded output count:"+count);
  long[][] output=new long[count][];for(int i=0;i<count;i++)output[i]=new long[]{Marshal.ReadInt64(entries,i*16),Marshal.ReadInt64(entries,i*16+8)};
  // All buffers remain process-local and are reclaimed when this isolated process exits.
  return output;
 }
}
'@
$inputs=@(@{name='positive-step';pairs=[long[]]@(0,0,100,150,200,200)},@{name='negative-step';pairs=[long[]]@(0,0,100,50,200,200)},@{name='constant-offset';pairs=[long[]]@(0,100)},@{name='reordered';pairs=[long[]]@(0,0,100,200,200,100,300,300)})
$rows=@();foreach($c in $inputs){$out=[ReverseOracle]::Run($c.pairs,0);$rows+=@{name=$c.name;input_flat=$c.pairs;start=0;output=$out}}
$rows|ConvertTo-Json -Depth 8
