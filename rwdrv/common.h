#pragma once
#include "struct.h"
#include <windef.h>
#define log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#define BB_POOL_TAG 'enoB'

typedef UINT(*PHookFn)(UINT, UINT, UINT);

struct DriverState
{
	bool Initialized;
	PVOID BaseAddress;
	PHookFn HookControl;
	PHookFn OriginalHookedFn;
	PDRIVER_DISPATCH OriginalDiskDispatchFn;
};

typedef struct _POOL_TRACKER_BIG_PAGES
{
	volatile ULONGLONG Va;                                                  //0x0
	ULONG Key;                                                              //0x8
	ULONG Pattern;                                                        //0xc
	ULONG PoolType;                                                      //0xc
	ULONG SlushSize;                                                     //0xc
	ULONGLONG NumberOfBytes;                                                //0x10
} POOL_TRACKER_BIG_PAGES, * PPOOL_TRACKER_BIG_PAGES;

typedef NTSTATUS(NTAPI OBREFERENCEOBJECTBYNAME)(
	PUNICODE_STRING ObjectPath,
	ULONG Attributes,
	PACCESS_STATE PassedAccessState OPTIONAL,
	ACCESS_MASK DesiredAccess OPTIONAL,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	PVOID ParseContext OPTIONAL,
	PVOID* ObjectPtr);

extern "C" __declspec(dllimport) OBREFERENCEOBJECTBYNAME ObReferenceObjectByName;
extern "C" __declspec(dllimport) POBJECT_TYPE* IoDriverObjectType;