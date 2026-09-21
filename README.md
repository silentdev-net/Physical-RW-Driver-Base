# KMDF Driver1

A Windows kernel-mode driver that exposes physical memory read/write primitives to a user-mode client through a named shared memory section. The driver walks the EPROCESS list to locate a target process, resolves its CR3 (with fallback and bruteforce strategies for cases where anti-cheat software swaps the directory table base), and performs arbitrary virtual address translation by manually walking the page table hierarchy using direct physical memory access.

Communication between the driver and client is done entirely through a shared section object. The client sets a command and flips the status field; the driver polls, executes, and signals completion. No IOCTLs, no DeviceIoControl, no device stack involvement at runtime after load.

## Project structure

```
KMDF Driver1/
    main.c          - DriverEntry, shared memory setup, command dispatch loop
    rw.c            - Physical memory access, VaToPhys, ReadPhys64, WriteProcessMemory
    process.c       - EPROCESS walk, CR3 resolution with fallback and bruteforce
    shared.h        - Command definitions and SHARED_MEMORY layout (shared with client)
    KMDFDriver1.inf - Driver installation INF

TestClient/
    main.cpp        - User-mode test client, exercises GET_CR3 and READ_MEM commands
```

## How it works

The driver allocates a nonpaged scratch page on init and resolves the PTE base address by pattern-scanning ntoskrnl for the MmGetVirtualForPhysical stub. This gives it the ability to remap the scratch page's PTE to any physical address, read or write the backing physical memory, then restore the original PTE and flush the TLB entry. All physical access goes through this single-page sliding window.

CR3 resolution tries three strategies in order:

1. Read DirectoryTableBase directly from EPROCESS at offset 0x28 and verify it by translating the process image base and checking for an MZ header at the resulting physical address.
2. Fall back to the user-mode DirectoryTableBase at offset 0x280, which some anti-cheat implementations swap in place of the kernel DTB.
3. Brute-force scan physical memory in a 256 MB window around the hint CR3, checking each 4K-aligned candidate by translating the image base virtual address and validating the MZ magic.

## Building

1. Open `KMDF Driver1.sln` in Visual Studio with the WDK installed.
2. Select `Debug | x64` or `Release | x64`.
3. Build solution.

Both configurations build without a code-signing certificate. The sign step is disabled in the project (`SignMode=Off`), so the output `.sys` is unsigned. You must have test-signing mode active on the target machine to load it either way.

Debug binary: `KMDF Driver1\x64\Debug\KMDF Driver1\KMDFDriver1.sys`
Release binary: `KMDF Driver1\x64\Release\KMDF Driver1\KMDFDriver1.sys`

If you want a properly signed release for distribution, set `SignMode` back to `ProdSign` in the project properties and point it at an EV certificate enrolled with Microsoft's driver signing portal.

## Loading the driver

Test signing must be enabled on the target machine:

```
bcdedit /set testsigning on
```

Reboot, then load the driver with sc or OSR Driver Loader. The driver creates the shared section on DriverEntry and tears it down on unload.

## Requirements

- Windows 10 x64, build 16299 or later (for DestinationDir 13 support in the INF) !!!WINDOWS 11 REMAINS UNTESTED!!!
- Visual Studio 2022 with the Windows Driver Kit installed
- For the client: any standard MSVC toolchain, no special dependencies
