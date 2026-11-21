# Hyperion NtCreateSection Detour

`version-f0ea5da9412f4e35`

A teardown of Hyperion's syscall-level detour on `NtCreateSection`, used to inspect `SEC_IMAGE` (DLL/image-backed) sections before they're mapped — covering the hook mechanism, the inspection pipeline for image-backed sections, the internal probe section it creates, the instrumentation-callback clear, and how each injected failure is handled.

> Addresses are tied to the build above and will shift on new clients — read the structure, not the numbers.

## Entry

The detour is at `0xa911b0`. A static slot at `0xf6aab8` contains its address:

```
F6AAB8  B0 11 A9 00 00 00 00 00  dq 0A911B0h
```

`ntdll.dll` exports `NtCreateSection` at RVA `0x1616f0`. Its service number is `0x4a`:

```asm
1801616F0  4C 8B D1                 mov r10, rcx
1801616F3  B8 4A 00 00 00           mov eax, 4Ah
1801616F8  F6 04 25 08 03 FE 7F 01  test byte ptr [7FFE0308h], 1
180161702  75 03                    jnz 180161707h
180161704  0F 05                    syscall
180161706  C3                       ret
```

Hyperion does not contain a `NtCreateSection` import or export name string. The detour uses **direct syscalls** with garbage in the high bits of `eax`; the low 12 bits select the service.

## WoW arguments

How the detour recovers the caller's seven `NtCreateSection` arguments:

| Argument | loc | RVA | regs |
|---|---|---|---|
| `SectionHandle` | `rcx` | `0xa911ce` | `rdi` |
| `DesiredAccess` | `rdx` | `0xa911cc` | `esi` |
| `ObjectAttributes` | `r8` | `0xa911c9` | `r15` |
| `MaximumSize` | `r9` | `0xa911c6` | `r13` |
| `SectionPageProtection` | `[rsp+0x28]` | `0xa913b3` | `r12d` |
| `AllocationAttributes` | `[rsp+0x30]` | `0xa912cb` | `ebx` |
| `FileHandle` | `[rsp+0x38]` | `0xa91293` | `r14` |

The first instructions are:

```asm
A911B0  56                    push rsi
A911B1  41 55                 push r13
A911B3  41 56                 push r14
A911B5  57                    push rdi
A911B6  55                    push rbp
A911B7  41 57                 push r15
A911B9  53                    push rbx
A911BA  41 54                 push r12
A911BC  48 83 EC 78           sub rsp, 78h
A911C0  44 0F 29 6C 24 60     movaps [rsp+60h], xmm13
A911C6  4D 89 CD              mov r13, r9
A911C9  4D 89 C7              mov r15, r8
A911CC  89 D6                 mov esi, edx
A911CE  48 89 CF              mov rdi, rcx
```

Entry signature for this version:

```
56 41 55 41 56 41 57 55 41 57 53 41 54 48 83 EC 78
44 0F 29 6C 24 60 4D 89 CD 4D 89 C7 89 D6 48 89 CF
```

## Non-image sections

When `AllocationAttributes` does not contain `SEC_IMAGE`, the detour skips inspection and reaches the original create at `0xa92813` directly.

Marked runs with `PAGE_READONLY`, `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`, null `ObjectAttributes`, null `MaximumSize`, and zero `DesiredAccess` all follow this path. Only the original `NtCreateSection` is issued.

## Image-backed sections

A file-backed section with `SEC_IMAGE` takes the inspection path. The successful x64 DLL run produces this sequence:

| Order | RVA | Service | Arguments and use |
|---|---|---|---|
| 1 | `0x9a84c9` | `NtQueryObject` | `FileHandle`, `ObjectNameInformation` (1), buffer `0x218`. Reads the object path. |
| 2 | `0x9a9a80` | `NtReadFile` | Reads `0x40` bytes at file offset 0. |
| 3 | `0x9aaca3` | `NtReadFile` | Reads `0x108` bytes at the NT-header offset, `0x40` in the marked file. |
| 4 | `0x5e1b55` | `NtQueryObject` | `FileHandle`, `ObjectBasicInformation` (0), buffer `0x38`. |
| 5 | `0x5e77dd` | `NtQueryInformationFile` | `FileStandardInformation` (5), buffer `0x18`. Supplies the file size. |
| 6 | `0x5e8509` | `NtCreateSection` | Creates an internal read-only section over the same `FileHandle`. |
| 7 | `0x5e97b0` | `NtMapViewOfSection` | Maps that section into the current process with `PAGE_READONLY`. |
| 8 | `0x5ed7cc` | `NtClose` | Closes the internal section handle. |
| 9 | `0x5ee500` | `NtQuerySystemInformation` | `SystemCodeIntegrityCertificateInformation` (`0xb7`), `0x10` bytes. |
| 10 | `0x66c9ad` | `NtSetInformationProcess` | `ProcessInstrumentationCallback` (`0x28`), a zeroed `0x10`-byte record. |
| 11 | `0x66cd5e` | `NtUnmapViewOfSection` | Unmaps the view from the current process. |
| 12 | `0xa92813` | `NtCreateSection` | Issues the caller's original create with all seven original arguments. |

## Internal section

The internal create at `0x5e8509` does not reuse the caller's protection or attributes. It forces a committed, read-only section:

```asm
5E84ED  mov [rsp+38h], r10     -> original FileHandle
5E84F2  mov [rsp+30h], r9d     -> SEC_COMMIT
5E84F7  mov [rsp+28h], r11d    -> PAGE_READONLY
5E84FC  lea r10, [rbp+var_550] -> output handle
5E8503  xor r9d, r9d           -> MaximumSize = NULL
5E8506  xor r8d, r8d           -> ObjectAttributes = NULL
5E8509  syscall
```

The arguments are:

```c
HANDLE probe;

NtCreateSection(
    &probe,
    0xf001f,                 // desired access
    NULL,                    // ObjectAttributes
    NULL,                    // MaximumSize
    PAGE_READONLY,           // 0x02
    SEC_COMMIT,              // 0x08000000
    FileHandle               // original file handle
);
```

The map at `0x5e97b0` uses the internal handle and current process. `InheritDisposition` is 2 (`ViewUnmap`), `AllocationType` is 0, and the view protection is `PAGE_READONLY`. The section offset and initial view size are zero.

## Code integrity and instrumentation

After mapping, Hyperion closes the internal handle and queries `SystemCodeIntegrityCertificateInformation` (`0xb7`) with a `0x10`-byte buffer and no `ReturnLength` pointer.

It then clears the process instrumentation callback:

```c
uint8_t callback_record[16] = {0};

NtSetInformationProcess(
    (HANDLE)-1,
    ProcessInstrumentationCallback, // 0x28
    callback_record,
    0x10
);

NtUnmapViewOfSection((HANDLE)-1, view);
```

The `0x10`-byte record is entirely zero in the successful run. This **clears** the callback; it does not install one. No restoration is observed after the unmap or after the original create.

## Original create

The final path restores the original register arguments and stack arguments:

```asm
A92569  mov eax, [rcx+r10+0x10] -> [0xf10760] = 0x82c2004a
A9256E  mov [rsp+38h], r14      -> FileHandle
A92573  jmp A927F7
A927F7  mov [rsp+30h], ebx      -> AllocationAttributes
A927FB  mov r10d, [rsp+0e0h]    -> saved SectionPageProtection
A92803  mov [rsp+28h], r10d
A92808  mov r10, rdi            -> SectionHandle
A9280B  mov edx, esi            -> DesiredAccess
A9280D  mov r9, r13             -> MaximumSize
A92810  mov r8, r15             -> ObjectAttributes
A92813  syscall
```

The service constant at `0xf10760` is `0x82c2004a`; its low 12 bits are `0x4a`.

The original call's `NTSTATUS` is returned to the caller unchanged. Injecting `STATUS_ACCESS_DENIED` at `0xa92813` returns `0xc0000022`.

## Failure handling

The failure paths are not uniform. Some failures skip inspection and continue to the original create; others reject the request with `STATUS_INVALID_IMAGE_HASH`.

| Injected failure | Result |
|---|---|
| `ObjectNameInformation` | Early return without the original syscall. |
| `ObjectBasicInformation` | Client error report, then `0xc0000428`. |
| DOS-header read | The NT-header read is skipped and inspection continues. |
| NT-header read | Continues with the zeroed header buffer. |
| `FileStandardInformation` | Skips the internal create and map path. |
| Internal `NtCreateSection` | Skips the map path. |
| `NtMapViewOfSection` | Closes the internal handle and continues. |
| Internal `NtClose` | Status ignored. |
| `SystemCodeIntegrityCertificateInformation` | Second CI query at `0x66af28`, callback clear, unmap, client report, then `0xc0000428`. |
| `NtSetInformationProcess` | Status ignored; unmap and original create continue. |
| `NtUnmapViewOfSection` | Status ignored. |
| Original `NtCreateSection` | Its status is returned unchanged. |

The two hard rejection paths return:

```c
STATUS_INVALID_IMAGE_HASH; // 0xc0000428
```

---

*`version-f0ea5da9412f4e35`. Structure is the takeaway — addresses shift every build.*
