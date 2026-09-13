#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <intrin.h>
// dont ask me how everything in this file works, even i dont know.
#pragma warning(disable: 4996)
NTKERNELAPI PVOID RtlPcToFileHeader(PVOID PcValue, PVOID* BaseOfImage);

#define PFN_MASK     0x0000FFFFFFFFF000ULL
#define PTE_P        1ULL
#define PTE_W        2ULL
#define LARGE_1G     (1ULL << 7)
#define LARGE_2M     (1ULL << 7)

typedef union _MMPTE {
    struct {
        ULONG64 Present : 1;
        ULONG64 Write : 1;
        ULONG64 User : 1;
        ULONG64 WriteThru : 1;
        ULONG64 NoCache : 1;
        ULONG64 Accessed : 1;
        ULONG64 Dirty : 1;
        ULONG64 LargePage : 1;
        ULONG64 Global : 1;
        ULONG64 Soft : 3;
        ULONG64 PageFrame : 36;
        ULONG64 Rsvd : 4;
        ULONG64 WsIndex : 11;
        ULONG64 NX : 1;
    } Hard;
    ULONG64 Value;
} MMPTE, * PMMPTE;

static ULONG64 g_PteBase = 0;
static PVOID   g_Scratch = NULL;
static PMMPTE  g_ScratchPte = NULL;

static PVOID FindPattern(PVOID Base, SIZE_T Size, const CHAR* Pat, const CHAR* Mask)
{
    SIZE_T len = strlen(Mask);
    SIZE_T i, j;
    for (i = 0; i < Size - len; i++)
    {
        BOOLEAN ok = TRUE;
        __try {
            for (j = 0; j < len; j++)
            {
                if (Mask[j] != '?' && Pat[j] != ((CHAR*)Base)[i + j])
                {
                    ok = FALSE; break;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { ok = FALSE; }
        if (ok) return (PVOID)((ULONG_PTR)Base + i);
    }
    return NULL;
}

static PVOID KernelBase(PULONG Size)
{
    PVOID base = NULL;
    RtlPcToFileHeader((PVOID)(ULONG_PTR)PsGetCurrentProcess, &base);
    if (base && Size)
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUCHAR)base + dos->e_lfanew);
        *Size = nt->OptionalHeader.SizeOfImage;
    }
    return base;
}

static ULONG64 ResolvePteBase(VOID)
{
    ULONG  ntSize = 0;
    PVOID  ntBase = KernelBase(&ntSize);
    if (!ntBase) return 0;

    PUCHAR found;
    ULONG64 candidate;

    // variant A: shr rcx,9 | mov rax,mask | and rcx,rax | mov rax,<PteBase>
    static const CHAR patA[] =
        "\x48\xC1\xE9\x09\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x23\xC8\x48\xB8";
    static const CHAR mskA[] = "xxxxxx????????xxxxx";

    found = FindPattern(ntBase, ntSize, patA, mskA);
    if (found)
    {
        candidate = *(ULONG64*)(found + 19);
        if ((candidate >> 48) == 0xFFFF) return candidate;
    }

    // variant B: shr rcx,9 | mov rax,<PteBase>
    static const CHAR patB[] = "\x48\xC1\xE9\x09\x48\xB8";
    static const CHAR mskB[] = "xxxxxx";

    found = FindPattern(ntBase, ntSize, patB, mskB);
    if (found)
    {
        candidate = *(ULONG64*)(found + 6);
        if ((candidate >> 48) == 0xFFFF) return candidate;
    }

    // variant B SAR
    static const CHAR patC[] = "\x48\xC1\xF9\x09\x48\xB8";
    found = FindPattern(ntBase, ntSize, patC, mskB);
    if (found)
    {
        candidate = *(ULONG64*)(found + 6);
        if ((candidate >> 48) == 0xFFFF) return candidate;
    }

    return 0;
}

static PMMPTE PteOf(PVOID Va)
{
    return (PMMPTE)(g_PteBase + (((ULONG64)Va >> 9) & 0x7FFFFFFFF8ULL));
}

ULONG64 ReadPhys64(ULONG64 Pa)
{
    volatile ULONG64* scrPte = (volatile ULONG64*)g_ScratchPte;
    ULONG64 old = *scrPte;
    ULONG64 neo = (old & ~PFN_MASK) | (Pa & PFN_MASK) | PTE_P;
    neo &= ~(1ULL << 63);

    _InterlockedExchange64((LONG64*)scrPte, (LONG64)neo);
    __invlpg(g_Scratch);

    ULONG64 val = *(volatile ULONG64*)((ULONG64)g_Scratch + (Pa & 0xFFF));
    _mm_lfence();

    _InterlockedExchange64((LONG64*)scrPte, (LONG64)old);
    __invlpg(g_Scratch);

    return val;
}

ULONG64 VaToPhys(ULONG64 Cr3, ULONG64 Va)
{
    ULONG64 e;

    e = ReadPhys64(Cr3 + ((Va >> 39) & 0x1FF) * 8);
    if (!(e & PTE_P)) return 0;

    e = ReadPhys64((e & PFN_MASK) + ((Va >> 30) & 0x1FF) * 8);
    if (!(e & PTE_P)) return 0;
    if (e & LARGE_1G) return (e & 0xFFFFC0000000ULL) + (Va & 0x3FFFFFFFULL);

    e = ReadPhys64((e & PFN_MASK) + ((Va >> 21) & 0x1FF) * 8);
    if (!(e & PTE_P)) return 0;
    if (e & LARGE_2M) return (e & 0xFFFFFFE00000ULL) + (Va & 0x1FFFFFULL);

    e = ReadPhys64((e & PFN_MASK) + ((Va >> 12) & 0x1FF) * 8);
    if (!(e & PTE_P)) return 0;

    return (e & PFN_MASK) + (Va & 0xFFFULL);
}

BOOLEAN InitMemory(VOID)
{
    g_PteBase = ResolvePteBase();
    if (!g_PteBase) return FALSE;

    g_Scratch = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'wMmK');
    if (!g_Scratch) return FALSE;

    g_ScratchPte = PteOf(g_Scratch);
    return TRUE;
}

NTSTATUS ReadProcessMemory(ULONG64 Cr3, ULONG64 Va, VOID* Dst, ULONG Size)
{
    volatile ULONG64* scrPte = (volatile ULONG64*)g_ScratchPte;
    ULONG done = 0, chunk, off, i;

    if (!g_Scratch || !g_ScratchPte) return STATUS_UNSUCCESSFUL;

    while (done < Size)
    {
        off = (ULONG)(Va & (PAGE_SIZE - 1));
        chunk = PAGE_SIZE - off;
        if (chunk > Size - done) chunk = Size - done;

        ULONG64 phys = VaToPhys(Cr3, Va);
        if (!phys) return done ? STATUS_PARTIAL_COPY : STATUS_INVALID_ADDRESS;

        ULONG64 old = *scrPte;
        ULONG64 neo = (old & ~PFN_MASK) | (phys & PFN_MASK) | PTE_P;
        neo &= ~(1ULL << 63);

        _InterlockedExchange64((LONG64*)scrPte, (LONG64)neo);
        __invlpg(g_Scratch);

        UCHAR* src = (UCHAR*)((ULONG64)g_Scratch + off);
        for (i = 0; i < chunk; i++) ((UCHAR*)Dst)[done + i] = src[i];
        _mm_lfence();

        _InterlockedExchange64((LONG64*)scrPte, (LONG64)old);
        __invlpg(g_Scratch);

        Va += chunk;
        done += chunk;
    }
    return STATUS_SUCCESS;
}

NTSTATUS WriteProcessMemory(ULONG64 Cr3, ULONG64 Va, const VOID* Src, ULONG Size)
{
    volatile ULONG64* scrPte = (volatile ULONG64*)g_ScratchPte;
    const UCHAR* src = (const UCHAR*)Src;
    ULONG done = 0, chunk, off, i;

    if (!g_Scratch || !g_ScratchPte) return STATUS_UNSUCCESSFUL;

    while (done < Size)
    {
        off = (ULONG)(Va & (PAGE_SIZE - 1));
        chunk = PAGE_SIZE - off;
        if (chunk > Size - done) chunk = Size - done;

        ULONG64 phys = VaToPhys(Cr3, Va);
        if (!phys) return done ? STATUS_PARTIAL_COPY : STATUS_INVALID_ADDRESS;

        ULONG64 old = *scrPte;
        ULONG64 neo = (old & ~PFN_MASK) | (phys & PFN_MASK) | PTE_P | PTE_W;
        neo &= ~(1ULL << 63);

        _InterlockedExchange64((LONG64*)scrPte, (LONG64)neo);
        __invlpg(g_Scratch);

        UCHAR* dst = (UCHAR*)((ULONG64)g_Scratch + off);
        for (i = 0; i < chunk; i++) dst[i] = src[done + i];
        _mm_sfence();

        _InterlockedExchange64((LONG64*)scrPte, (LONG64)old);
        __invlpg(g_Scratch);

        Va += chunk;
        done += chunk;
    }
    return STATUS_SUCCESS;
}