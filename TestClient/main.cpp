#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "../KMDF Driver1/shared.h"


DWORD GetProcessInfoByName(const wchar_t* processName, ULONG64* outBaseAddress) {
	DWORD pid = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	PROCESSENTRY32W pe = { sizeof(pe) };
	if (Process32FirstW(snapshot, &pe)) {
		do {
			if (_wcsicmp(pe.szExeFile, processName) == 0) {
				pid = pe.th32ProcessID;
				break;
			}
		} while (Process32NextW(snapshot, &pe));
	}
	CloseHandle(snapshot);

	if (pid == 0) {
		return 0;
	}

	if (outBaseAddress) {
		*outBaseAddress = 0;
		HANDLE modSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
		if (modSnapshot != INVALID_HANDLE_VALUE) {
			MODULEENTRY32W me = { sizeof(me) };
			if (Module32FirstW(modSnapshot, &me)) {
				*outBaseAddress = (ULONG64)me.modBaseAddr;
			}
			CloseHandle(modSnapshot);
		}
	}

	return pid;
}

BOOL SendCommand(PSHARED_MEMORY shm) {
	InterlockedExchange(&shm->Status, SHM_PENDING);
	while (shm->Status == SHM_PENDING) {
		Sleep(0);
	}
	return shm->Status == SHM_COMPLETE;
}

int main() {
	printf("opening shared memory\n");
	HANDLE hMapping = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, SHM_SECTION_NAME_UM);
	if (hMapping == NULL) {
		printf("error: %lu\n", GetLastError());
		system("pause");
		return 1;
	}

	PSHARED_MEMORY shm = (PSHARED_MEMORY)MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SHARED_MEMORY) + SHM_DATA_MAX);
	if (shm == NULL) {
		printf("MapViewOfFile error: %lu\n", GetLastError());
		CloseHandle(hMapping);
		system("pause");
		return 1;
	}
	printf("connected to driver\n\n");

	printf("searching for notepad\n");
	ULONG64 baseAddress = 0;
	DWORD pid = GetProcessInfoByName(L"notepad.exe", &baseAddress);
	if (pid == 0) {
		printf("couldnt find notepad\n");
		UnmapViewOfFile(shm);
		CloseHandle(hMapping);
		system("pause");
		return 1;
	}

	printf("found notepad.exe pid: %lu\n", pid);
	printf("notepad base addr: 0x%llX\n\n", baseAddress);
	printf("getting cr3\n");
	shm->Command = CMD_GET_CR3;
	shm->Pid = pid;

	if (!SendCommand(shm) || shm->Cr3 == 0) {
		printf("getcr3 failed (cr3: 0x%llX)\n", shm->Cr3);
		UnmapViewOfFile(shm);
		CloseHandle(hMapping);
		system("pause");
		return 1;
	}
	printf("target cr3 = 0x%llX\n\n", shm->Cr3);

	if (baseAddress != 0) {
		printf("reading dos header at 0x%llX...\n", baseAddress);
		shm->Command = CMD_READ_MEM;
		shm->Address = baseAddress;
		shm->Size = 16;

		if (SendCommand(shm) && shm->ResultSize > 0) {
			printf("read %lu bytes from notepad\n", shm->ResultSize);
			printf("magic bytes: %c%c\n", shm->Data[0], shm->Data[1]);
			printf("hex dump: ");
			for (ULONG i = 0; i < shm->ResultSize; i++) {
				printf("%02X ", shm->Data[i]);
			}
			printf("\n\n");
		} else {
			printf("read failed\n\n");
		}
	}

	printf("test complete\n");
	UnmapViewOfFile(shm);
	CloseHandle(hMapping);
	system("pause");
	return 0;
}
