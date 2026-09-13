#include <ntifs.h>
#include <ntddk.h>
#include "shared.h"
ULONG64 GetCr3(HANDLE targetPid);
BOOLEAN InitMemory(VOID);
NTSTATUS ReadProcessMemory(ULONG64 Cr3, ULONG64 Va, VOID* Dst, ULONG Size);
NTSTATUS WriteProcessMemory(ULONG64 Cr3, ULONG64 Va, const VOID* Src, ULONG Size);
static HANDLE g_SectionHandle = NULL;
static PVOID g_SectionObject = NULL;
static PSHARED_MEMORY g_Shm = NULL;
static HANDLE g_ThreadHandle = NULL;
static KEVENT g_StopEvent;

static VOID WorkerThread(_In_ PVOID Context) {
	UNREFERENCED_PARAMETER(Context);
	LARGE_INTEGER interval;
	interval.QuadPart = -1000;
	while (KeReadStateEvent(&g_StopEvent) == 0) {
		if (g_Shm->Status == SHM_PENDING) {
			NTSTATUS status = STATUS_SUCCESS;
			switch (g_Shm->Command) {

			case CMD_GET_CR3:
			{
				ULONG64 cr3 = GetCr3((HANDLE)(ULONG_PTR)g_Shm->Pid);
				g_Shm->Cr3 = cr3;
				g_Shm->ResultSize = 0;
				break;
			}
			case CMD_READ_MEM:
			{
				ULONG size = g_Shm->Size;
				if (size > SHM_DATA_MAX) {
					size = SHM_DATA_MAX;
				}
				status = ReadProcessMemory(g_Shm->Cr3, g_Shm->Address, g_Shm->Data, size);
				g_Shm->ResultSize = NT_SUCCESS(status) ? size : 0;
				break;
			}
			case CMD_WRITE_MEM:
			{
				status = WriteProcessMemory(g_Shm->Cr3, g_Shm->Address, g_Shm->Data, g_Shm->Size);
				g_Shm->ResultSize = 0;
				break;
			}
			default:
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			g_Shm->NtStatus = (LONG)status;
			_InterlockedExchange(&g_Shm->Status, NT_SUCCESS(status) ? SHM_COMPLETE : SHM_ERROR);
		}
		KeDelayExecutionThread(KernelMode, FALSE, &interval);
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID UnloadRoutine(_In_ PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	KeSetEvent(&g_StopEvent, IO_NO_INCREMENT, FALSE);
	if (g_ThreadHandle) {
		PVOID threadObj;
		ObReferenceObjectByHandle(g_ThreadHandle, THREAD_ALL_ACCESS, NULL, KernelMode, &threadObj, NULL);
		KeWaitForSingleObject(threadObj, Executive, KernelMode, FALSE, NULL);
		ObDereferenceObject(threadObj);
		ZwClose(g_ThreadHandle);
	}
	if (g_Shm) {
		MmUnmapViewInSystemSpace(g_Shm);
	}
	if (g_SectionObject) {
		ObDereferenceObject(g_SectionObject);
	}
	if (g_SectionHandle) {
		ZwClose(g_SectionHandle);
	}
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status;

	if (!InitMemory()) {
		DbgPrint("InitMemory failed\n");
		return STATUS_UNSUCCESSFUL;
	}

	SECURITY_DESCRIPTOR sd;
	RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	RtlSetDaclSecurityDescriptor(&sd, TRUE, NULL, FALSE);
	UNICODE_STRING sectionName = RTL_CONSTANT_STRING(SHM_SECTION_NAME);
	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE, NULL, &sd);
	LARGE_INTEGER sectionSize;
	sectionSize.QuadPart = sizeof(SHARED_MEMORY) + SHM_DATA_MAX;
	status = ZwCreateSection(&g_SectionHandle, SECTION_ALL_ACCESS, &objAttr, &sectionSize, PAGE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(status)) {
		DbgPrint("ZwCreateSection failed: 0x%X\n", status);
		return status;
	}
	status = ObReferenceObjectByHandle(g_SectionHandle, SECTION_ALL_ACCESS, NULL, KernelMode, &g_SectionObject, NULL);
	if (!NT_SUCCESS(status)) {
		DbgPrint("ObReferenceObjectByHandle failed: 0x%X\n", status);
		ZwClose(g_SectionHandle);
		return status;
	}
	SIZE_T viewSize = 0;
	status = MmMapViewInSystemSpace(g_SectionObject, (PVOID*)&g_Shm, &viewSize);
	if (!NT_SUCCESS(status)) {
		DbgPrint("MmMapViewInSystemSpace failed: 0x%X\n", status);
		ObDereferenceObject(g_SectionObject);
		ZwClose(g_SectionHandle);
		return status;
	}

	RtlZeroMemory(g_Shm, viewSize);
	KeInitializeEvent(&g_StopEvent, NotificationEvent, FALSE);
	status = PsCreateSystemThread(&g_ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, WorkerThread, NULL);

	if (!NT_SUCCESS(status)) {
		DbgPrint("PsCreateSystemThread failed: 0x%X\n", status);
		MmUnmapViewInSystemSpace(g_Shm);
		ObDereferenceObject(g_SectionObject);
		ZwClose(g_SectionHandle);
		return status;
	}

	DriverObject->DriverUnload = UnloadRoutine;

	return STATUS_SUCCESS;
}
