.assembly extern mscorlib {}
.assembly OriginalMixed {}
.module OriginalMixed.dll
.class public auto ansi OriginalMixed extends [mscorlib]System.Object {
.method public static int32 ManagedAdd(int32 a, int32 b) cil managed { .maxstack 2 ldarg.0 ldarg.1 add ret }
.method public static int32 NativeOp(int32 a, int32 b) native unmanaged { .emitbyte 0x8b .emitbyte 0xc1 .emitbyte 0x2b .emitbyte 0xc2 .emitbyte 0xc3 }
}
