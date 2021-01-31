#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include "clean.hpp"
#include "common.h"
#include "skcrypt.h"

DriverState g_driverState;

inline NTSTATUS BoolToNt(const bool b)
{
	return b ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}


UINT __fastcall HookControl(UINT a1, UINT a2, UINT a3)
{
	log(skCrypt("[rwdrv] Hook called!, args [0x%X] [0x%X] [0x%X]\n"), a1, a2, a3);

	if (a1 == 0xDEADBEEF)
	{
		if (!g_driverState.Initialized)
		{
			log(skCrypt("[rwdrv] Received Init command\n"));
			return BoolToNt(
				   NT_SUCCESS(Clear::SpoofDiskSerials())
				&& NT_SUCCESS(Clear::ClearSystemBigPoolInfo(g_driverState.BaseAddress))
				// TODO Clear::ClearPfnDatabase();
			);
		}
		// TODO Control codes
		return 0x12345678;
	}
	else return g_driverState.OriginalHookedFn(a1, a2, a3);
}

NTSTATUS SetupHook()
{
	// uint ApiSetEditionOpenInputDesktopEntryPoint(uint, uint, uint);	
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

	const auto movInstruction = qwordPtr - 0x11; // Start of the mov instruction

	const auto ripReg = movInstruction + 0x7; // RIP register

	// Skip 3 opcode bytes and read next 4 bytes, then add them to the RIP register

	const auto fnPtrLocation = ripReg + *reinterpret_cast<unsigned int*>(movInstruction + 0x3);

	log(skCrypt("[rwdrv] Function pointer location at [0x%p]\n"), PVOID(fnPtrLocation));

	log(skCrypt("[rwdrv] Original function address: [0x%p]\n"), *reinterpret_cast<PVOID*>(fnPtrLocation));

	*reinterpret_cast<PVOID*>(&g_driverState.OriginalHookedFn) = InterlockedExchangePointer(
		reinterpret_cast<PVOID*>(fnPtrLocation), PVOID(HookControl));

	log(skCrypt("[rwdrv] Successfully placed hook\n"));

	return STATUS_SUCCESS;
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
