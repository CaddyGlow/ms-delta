#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
clang-cl --target=aarch64-pc-windows-msvc /c /O1 /GS- /DREVISION=1 /Fosource.obj tiny.c
lld-link /entry:mainCRTStartup /subsystem:console /nodefaultlib /machine:arm64 /base:0x140000000 /out:source.exe source.obj
clang-cl --target=aarch64-pc-windows-msvc /c /O1 /GS- /DREVISION=2 /DSHIFT /Fotarget.obj tiny.c
lld-link /entry:mainCRTStartup /subsystem:console /nodefaultlib /machine:arm64 /base:0x183000000 /out:target.exe target.obj
