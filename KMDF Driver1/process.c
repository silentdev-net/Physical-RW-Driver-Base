#include <ntddk.h>
#define EPROCESS_UNIQUE_PROCESS_ID_OFFSET 0x440
#define EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET 0x448
// these should work on all versions of win 10-11
#define EPROCESS_DIRECTORY_TABLE_BASE_OFFSET 0x028
#define USER_DIRECTORYTABLEBASE 0x280
#define EPROCESS_SECTION_BASE_ADDRESS_OFFSET 0x520 

#define MZ_HEADER 0x5A4D // change if you are trying to find cr3 of something that isnt an executable
static ULONG64 BruteforceCr3(ULONG64 HintCr3, ULONG64 TestVa);
extern ULONG64 ReadPhys64(ULONG64 Pa);
extern ULONG64 VaToPhys(ULONG64 Cr3, ULONG64 Va);

static BOOLEAN VerifyCr3(ULONG64 Cr3, ULONG64 TestVa) {
	if (Cr3 == 0 || TestVa == 0) {
		return FALSE;
	}
	ULONG64 phys = VaToPhys(Cr3, TestVa);
	if (phys == 0) {
		return FALSE;
	}
	ULONG64 headerQword = ReadPhys64(phys);
	USHORT magic = (USHORT)(headerQword & 0xFFFF);

	if (magic == MZ_HEADER) {
		DbgPrint("CR3 Verified");
		return TRUE;
	}
	DbgPrint("Failed to verify CR3");
	return FALSE;
}

ULONG64 GetCr3(HANDLE targetPid) {
	PEPROCESS currentprocess = PsGetCurrentProcess();
	if (!currentprocess) {
		return 0;
	}
	PLIST_ENTRY processListHead = (PLIST_ENTRY)((ULONG_PTR)currentprocess + EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET);

	PLIST_ENTRY currentEntry = processListHead->Flink;

	while (currentEntry != processListHead) {
		PEPROCESS process = (PEPROCESS)(
			(ULONG_PTR)currentEntry - EPROCESS_ACTIVE_PROCESS_LINKS_OFFSET
			);
		HANDLE pid = *(PHANDLE)(
			(ULONG_PTR)process + EPROCESS_UNIQUE_PROCESS_ID_OFFSET
			);
		if (pid == targetPid) {
			ULONG64 Cr3 = *(PULONG64)(
				(ULONG_PTR)process + EPROCESS_DIRECTORY_TABLE_BASE_OFFSET
				);

			ULONG64 imageBase = *(PULONG64)(
				(ULONG_PTR)process + EPROCESS_SECTION_BASE_ADDRESS_OFFSET);

			DbgPrint("eprocess walk: PID %llu -> CR3 = 0x%llX\n", (ULONG64)(ULONG_PTR)targetPid, Cr3);

			if (VerifyCr3(Cr3, imageBase)) {
				DbgPrint("EPROCESS cr3 is verified as correct");
				return Cr3;
			}

			// trying fallback 1 which is using USER_DIRECTORYTABLEBASE
			ULONG64 userCr3 = *(PULONG64)(
				(ULONG_PTR)process + USER_DIRECTORYTABLEBASE);
			if (userCr3 != 0 && userCr3 != Cr3) {
				DbgPrint("trying fallback 1...");
				if (VerifyCr3(userCr3, imageBase)) {
					DbgPrint("fallback 1. DTB is verified as correct");
					return userCr3;
				}
			}

			// trying to bruteforce the cr3
			DbgPrint("trying to bruteforce cr3...");
			ULONG64 realCr3 = BruteforceCr3(Cr3, imageBase);
			if (realCr3 != 0) {
				return realCr3;
			}

			DbgPrint("cr3 bruteforcing failed, returning eprocess walk cr3");
			return Cr3;
		}

		currentEntry = currentEntry->Flink;
	}

	DbgPrint("eprocess walk: PID %llu not found.\n", (ULONG64)(ULONG_PTR)targetPid);
	return 0;

}	

static ULONG64 BruteforceCr3(ULONG64 HintCr3, ULONG64 TestVa) {
	extern ULONG64 VaToPhys(ULONG64 Cr3, ULONG64 Va);
	extern ULONG64 ReadPhys64(ULONG64 Pa);
	PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
	if (!ranges) {
		DbgPrint("Failed MmGetPhysicalMemoryRanges()");
		return 0;
	}

	ULONG64 rangeSize = 256ULL * 1024 * 1024;
	ULONG64 hintLow = (HintCr3 > rangeSize) ? (HintCr3 - rangeSize) & ~0xFFFULL : 0;
	ULONG64 hintHigh = HintCr3 + rangeSize;

	for (ULONG i = 0; ranges[i].BaseAddress.QuadPart || ranges[i].NumberOfBytes.QuadPart; i++) {
		ULONG64 base = (ULONG64)ranges[i].BaseAddress.QuadPart;
		ULONG64 size = (ULONG64)ranges[i].NumberOfBytes.QuadPart;
		ULONG64 end = base + size;
		ULONG64 scanStart = max(base, hintLow) & ~0xFFFULL;
		ULONG64 scanEnd = min(end, hintHigh);

		if (scanStart >= scanEnd) {
			continue;
		}

		for (ULONG64 candidate = scanStart; candidate < scanEnd; candidate += PAGE_SIZE) {
			ULONG64 phys = VaToPhys(candidate, TestVa);
			if (phys == 0) {
				continue;
			}
			ULONG64 headerQword = ReadPhys64(phys);
			if ((headerQword & 0xFFFF) == MZ_HEADER) {
				DbgPrint("CR3 Bruteforce, found cr3");
				ExFreePool(ranges);
				return candidate;
			}
		}
	}

	for (ULONG i = 0; ranges[i].BaseAddress.QuadPart || ranges[i].NumberOfBytes.QuadPart; i++) {
		ULONG64 base = (ULONG64)ranges[i].BaseAddress.QuadPart;
		ULONG64 size = (ULONG64)ranges[i].NumberOfBytes.QuadPart;
		ULONG64 end = base + size;

		for (ULONG64 candidate = base & ~0xFFFULL; candidate < end; candidate += PAGE_SIZE) {
			if (candidate >= hintLow && candidate < hintHigh) {
				continue;
			}

			ULONG64 phys = VaToPhys(candidate, TestVa);
			if (phys == 0) {
				continue;
			}

			ULONG64 headerQword = ReadPhys64(phys);
			if ((headerQword & 0xFFFF) == MZ_HEADER) {
				DbgPrint("CR3 found using bruteforcing");
				ExFreePool(ranges);
				return candidate;
			}
		}
	}

	DbgPrint("Couldnt get CR3 using bruteforce");
	ExFreePool(ranges);
	return 0;
}

