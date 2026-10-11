#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
clang-cl --target=thumbv7-pc-windows-msvc /c /O1 /GS- /DREVISION=1 /Fosource.obj tiny.c
lld-link /entry:mainCRTStartup /subsystem:console /nodefaultlib /machine:arm /base:0x400000 /out:source.exe source.obj
clang-cl --target=thumbv7-pc-windows-msvc /c /O1 /GS- /DREVISION=2 /DSHIFT /Fotarget.obj tiny.c
lld-link /entry:mainCRTStartup /subsystem:console /nodefaultlib /machine:arm /base:0x530000 /out:target.exe target.obj
