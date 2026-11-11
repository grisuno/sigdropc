# sigdrop (C port)

C translation of the `SigDrop.cpp` PoC from MSNightmare/SignDrop
(Windows CLFS authentication 0day LPE, MIT license), buildable with
`x86_64-w64-mingw32-gcc`.

## Build

    make            # -> sigdrop.exe (PE32+ x64, hid.dll payload embedded in .rsrc)
    make install-lab # stage into ~/.winbox/shared (Z:\ of the WinBox lab VM)

## Port notes (from SigDrop.cpp)

- winternl.h types/consts inlined (UNICODE_STRING, OBJECT_ATTRIBUTES,
  IO_STATUS_BLOCK, FILE_* create options, NTSTATUS codes).
- ntdll NtCreateFile / RtlInitUnicodeString / NtCreateSymbolicLinkObject
  resolved via GetProcAddress (no -lntdll dependency).
- std::wstring / make_unique replaced with fixed wchar_t buffers + malloc.
- StringFromGUID2 takes &guid (REFGUID).
- FILE_DISPOSITION_INFO field is `DeleteFile` under mingw (not DeleteFileW).
- printf %ws -> %ls (mingw printf).
- windefend_c.c (MIDL RPC client stubs) fixes to build with GCC:
  - entire file is under `#if defined(_M_AMD64)` (MSVC macro) -> build with -D_M_AMD64;
  - MSVC tolerates `extern const X y;` forward decls followed by
    `static const X y = ...` definitions; GCC does not -> declarations
    normalized to `static const` in-tree.

## Test result (WinBox gym, win11 24H2+, snapshot 2026-11-11)

    HKLM\SYSTEM\CurrentControlSet\Services\CLFS\Authentication : Mode = 0x3
    Defender ON -> run as SYSTEM: all stages OK
    -> "This machine is not vulnerable."   (mode 2/3 = enforcement)

Mode 0 or 1 (learning) + Defender ON is the vulnerable configuration; the
full chain needs a medium-integrity caller (run with
`--user winbox --password 'WinboxP@ss123'`, though the winbox guest agent
does not stream stdout for --user execs).

## LazyOwn addon

`~/LazyOwn/lazyaddons/sigdrop.yaml` — orchestrates the gym test:
registry Mode check, Defender posture, staging and execution.

    lazyown_set_config poc_binary=/home/grisun0/src_note/c/signdrop/sigdrop.exe
    python3 lazyown.py --headless --json-output --run-chain "sigdrop"

Operator params live in `~/LazyOwn/params/operator.yaml` (poc_binary, poc_exec_opts, poc_timeout).
(poc_binary, poc_exec_opts, poc_timeout).

## Patch-state deep-dive (2026-11-11, follow-up)

Question: is the guest truly patched, or was the port broken? Both signals
independently say patched, and the port was proven live:

1. **The PoC reaches the designed decision point.** The debug build walks the
   full pipeline — workdir, CLFS log via `\CLFS` device, object-manager
   symlinks, Negotiate IOCTL into clfs.sys (0x8007A808) — every stage OK. The
   "not vulnerable" verdict comes from the *intended* path (`.cnpf` absent
   after successful container setup), not an error path. A broken port would
   have failed earlier with "Failed to create …" and exit 1.
2. **CLFS enforcement is durably active.** Writing `Mode=1` (learn) or
   `Mode=0` via reg.exe and rebooting gets rewritten to `Mode=0x3` by the
   kernel on the next start: the 120-day adoption window
   (`EnforcementTransitionPeriod = 0x9e3400`) already elapsed, so clfs.sys
   auto-transitions to enforcement and persists it. In-guest registry edits
   cannot durably disable the mitigation on this build.
3. Registry and PoC agree: `Mode=0x3` (enforcement) ⟺ `.cnpf` never
   auto-created ⟺ not exploitable by SignDrop.

To test the vulnerable path end-to-end you need a guest whose adoption window
has NOT elapsed (fresh install or a reset transition clock) in Mode 0/1.


[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Y8Y2Z73AV)
