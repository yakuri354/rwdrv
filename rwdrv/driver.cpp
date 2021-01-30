#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>

#include "../../../../../../Program Files (x86)/Windows Kits/10/Include/10.0.19041.0/um/apiquery2.h"
#include "clean.hpp"
#include "skcrypt.h"

typedef INT64 (*HookedFnPtr)(UINT, UINT, UINT);

struct DriverState
{
	bool Initialized;
	PVOID BaseAddress;
};

DriverState g_driverState;

inline NTSTATUS BoolToNt(const bool b)
{
	return b ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS SetupHook()
{
	DbgBreakPoint();
	// ApiSetEditionOpenInputDesktopEntryPoint(uint, uint, uint);	
	const auto qwordPtr = Search::FindPattern(
		UINT64(Search::Win32kBase),
		Search::Win32kSize,
		reinterpret_cast<BYTE*>("\x8B\xCD\xFF\x15\x00\x00\x00\x00\x48\x8B\xD8"),
		skCrypt("xxxx????xxx")
	);
	
	if (qwordPtr == NULL)
	{
		log(skCrypt("[rwdrv] Failed to locate qword_ptr\n"));
		return STATUS_UNSUCCESSFUL;
	}

	log(skCrypt("[rwdrv] Found qword_ptr call at [0x%p]\n"), PVOID(qwordPtr));


	auto qwordPtrDeref = UINT64(qwordPtr) - 0xA;
	qwordPtrDeref = UINT64(qwordPtrDeref) + *PINT(PBYTE(qwordPtrDeref) + 3) + 7;

	log(skCrypt("[rwdrv] Function pointer location at [0x%p]\n"), PVOID(qwordPtrDeref));

	DbgBreakPoint();

	return STATUS_SUCCESS;
}

INT64 __fastcall HookControl(UINT a1, UINT a2, UINT a3)
{
	log(skCrypt("[rwdrv] Hook called!, args [%ud] [%ud] [%ud]\n"), a1, a2, a3);
	
	return 0;
}

NTSTATUS InitRoutine(PVOID baseAddr)
{
	g_driverState.BaseAddress = baseAddr;

	const auto status = Search::SetKernelProps();
	if (!NT_SUCCESS(status))
	{
		log(skCrypt("[rwdrv] Failed to obtain kernel modules\n"));
		return STATUS_UNSUCCESSFUL;
	}

	return status;
}

NTSTATUS DriverEntry(PVOID baseAddress)
{
	log(skCrypt("[rwdrv] Driver loaded at [0x%p]\n"), baseAddress);
	DbgBreakPoint();

	auto status = InitRoutine(baseAddress);
	if (!NT_SUCCESS(status))
	{
		log(skCrypt("[rwdrv] Driver initialization routine failed.\n"));
		return status;
	}

	status = SetupHook();
	if (!NT_SUCCESS(status))
	{
		log(skCrypt("[rwdrv] Failed to setup communication hook\n"));
		return status;
	}

	return status;
}
