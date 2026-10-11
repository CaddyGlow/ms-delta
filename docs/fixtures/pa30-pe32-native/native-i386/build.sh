#!/usr/bin/env bash
set -eu
fixture_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
build_dir="$(mktemp -d /tmp/pa30-i386-build.XXXXXX)"
clang-cl --target=i686-pc-windows-msvc /c /O1 /GS- "/Fo$build_dir/helper.obj" "$fixture_dir/helper.c"
lld-link /dll /noentry /nodefaultlib /machine:x86 /safeseh:no /timestamp:0 "/out:$fixture_dir/helper.dll" "/implib:$build_dir/helper.lib" "$build_dir/helper.obj"
clang-cl --target=i686-pc-windows-msvc /c /O1 /GS- /DREVISION=1 "/Fo$build_dir/source.obj" "$fixture_dir/tiny.c"
clang-cl --target=i686-pc-windows-msvc /c /O1 /GS- /DREVISION=2 /DSHIFT=1 "/Fo$build_dir/target.obj" "$fixture_dir/tiny.c"
clang-cl --target=i686-pc-windows-msvc /c "/Fo$build_dir/branch-source.obj" "$fixture_dir/branch-source.s"
clang-cl --target=i686-pc-windows-msvc /c "/Fo$build_dir/branch.obj" "$fixture_dir/branch.s"
clang-cl --target=i686-pc-windows-msvc /c /O1 /GS- "/Fo$build_dir/loadcfg.obj" "$fixture_dir/loadcfg.c"
lld-link /entry:mainCRTStartup /subsystem:console /nodefaultlib /machine:x86 /safeseh:no /dynamicbase /fixed:no /timestamp:0 "/out:$fixture_dir/source.exe" "$build_dir/source.obj" "$build_dir/branch-source.obj" "$build_dir/loadcfg.obj" "$build_dir/helper.lib"
lld-link /entry:mainCRTStartup /subsystem:console /nodefaultlib /machine:x86 /safeseh:no /dynamicbase /fixed:no /base:0x500000 /timestamp:0 "/out:$fixture_dir/target.exe" "$build_dir/target.obj" "$build_dir/branch.obj" "$build_dir/loadcfg.obj" "$build_dir/helper.lib"
