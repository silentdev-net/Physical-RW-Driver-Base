#pragma once
#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#endif

#define SHM_SECTION_NAME	L"\\BaseNamedObjects\\Driver"
#define SHM_SECTION_NAME_UM	"Global\\Driver"
#define SHM_DATA_MAX		0x10000

#define CMD_NONE		0
#define CMD_GET_CR3		1
#define CMD_READ_MEM	2
#define CMD_WRITE_MEM	3

#define SHM_IDLE		0
#define SHM_PENDING		1
#define SHM_COMPLETE	2
#define SHM_ERROR		3

typedef struct _SHARED_MEMORY {
	volatile LONG Status;
	ULONG Command;
	ULONG64 Cr3;
	ULONG64 Pid;
	ULONG64 Address;
	ULONG Size;
	ULONG ResultSize;
	LONG NtStatus;
	UCHAR Data[1];
} SHARED_MEMORY, *PSHARED_MEMORY;