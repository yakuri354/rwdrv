#define NO_DDK
#include <ntifs.h>
#include "common.hpp"
#include "clean.hpp"
#include "search.hpp"
#include "util.hpp"
#include "skcrypt.hpp"
#include "comms.hpp"
#include "intrin.h"

PVOID g::KernelBase;

struct _DriverState
{
	bool Initialized;
	PVOID BaseAddress;
	ULONG ImageSize;
	PVOID OriginalSyscallFn;
	PVOID OriginalWmiFn;
	PDRIVER_DISPATCH OriginalDiskDispatchFn;
	PVOID SharedMemory;
};

namespace g
{
	::_DriverState DriverState{};
}

NTSTATUS CleanupMiscTraces()
{
	auto status = Clear::SpoofDiskSerials(Search::KernelBase, &g::DriverState.OriginalDiskDispatchFn);
	if (!NT_SUCCESS(status))
	{
		log(skCrypt("[rwdrv] Spoofing disk serials failed\n"));
		return status;
	}
	status = Clear::ClearSystemBigPoolInfo(g::DriverState.BaseAddress);
	if (!NT_SUCCESS(status))
	{
		log(skCrypt("[rwdrv] Clearing BigPoolInfo failed\n"));
		return status;
	}
	status = Clear::ClearPfnEntry(g::DriverState.BaseAddress, g::DriverState.ImageSize);
	if (!NT_SUCCESS(status))
	{
		log(skCrypt("[rwdrv] Clearing Pfn table entry failed\n"));
		return status;
	}
	return STATUS_SUCCESS;
}

UINT64 __fastcall HookControl(UINT64 a1, UINT64 a2, UINT64 a3, UINT16 a4, UINT64 a5, UINT64 a6, UINT64 a7)
{
	// log(skCrypt("[rwdrv] Hook called!, args [0x%p] [0x%p] [0x%p] [%C] [0x%p] [0x%p] [0x%p]\n"), PVOID(a1), PVOID(a2), PVOID(a3), a4, PVOID(a5), PVOID(a6), PVOID(a7));

	if (a1 == CTL_MAGIC)
	{
		log(skCrypt("[rwdrv] Ctl called, code [%x]"), UINT32(a4));
		// TODO Control codes
		// TODO Shared memory
		return STATUS_SUCCESS;
	}
	
	if (!g::DriverState.Initialized && a4 == CTL_INIT_MAGIC)
	{

		log(skCrypt("[rwdrv] Initializing; Shared memory at [%p]\n"), PVOID(a1));

		g::DriverState.SharedMemory = PVOID(a1);

		log(skCrypt("[rwdrv] CR3 [0x%p]"), __readcr3());

		if (C_FN(MmIsAddressValid)(g::DriverState.SharedMemory))
		{
			*PUINT64(g::DriverState.SharedMemory) = CTL_MAGIC;
		}
		else
		{
			log(skCrypt("[rwdrv] Bad shared memory Va\n"));
		}

		log(skCrypt("[rwdrv] Cleaning up traces"));

		return CleanupMiscTraces();
	}

	if (a2 == 43 && a6 == 4 && a7 == 0)
	{
		log(skCrypt("Restoring Wmi call"));
		return _WmiTraceMessage(g::DriverState.OriginalWmiFn)(a1, a2, a3, a4, a5, a6, a7);
	}
	log(skCrypt("Restoring syscall: [0x%p] [0x%x]"), PVOID(a1), UINT32(a4));
	return PHookFn(g::DriverState.OriginalSyscallFn)(a1, a4);
}


NTSTATUS SetupHook()
{
	// The outside function, first in the chain
	// __int64 __fastcall ApiSetEditionFindThreadPointerData(__int64 a1, unsigned __int16 a2)
	const auto enclosingFn = Search::FindPattern(
		UINT64(Search::Win32kBase),
		Search::Win32kSize,
		PUCHAR(PCHAR(skCrypt("\xE8\x00\x00\x00\x00\x45\x33\xD2\x48\x8B\xD8"))),
		skCrypt("x????xxxxxx")
	);

	if (enclosingFn == NULL)
	{
		log(skCrypt("[rwdrv] Failed to locate syscall\n"));
		return STATUS_UNSUCCESSFUL;
	}

	auto* const syscallDataPtr = Search::ResolveEnclosingSig(enclosingFn, 0x7D);

	log(skCrypt("[rwdrv] Syscall pointer location at [0x%p]\n"), PVOID(syscallDataPtr));

	const auto rtLogFn = Search::FindPattern(
		UINT64(Search::RtBase),
		Search::RtSize,
		PUCHAR(PCHAR(skCrypt("\xE8\x00\x00\x00\x00\x85\xDB"))),
		skCrypt("x????xx")
	);

	if (rtLogFn == NULL)
	{
		log(skCrypt("[rwdrv] Failed to locate realtek log function\n"));
		return STATUS_UNSUCCESSFUL;
	}
	DbgBreakPoint();
	auto* const rtDataPtr = Search::ResolveEnclosingSig(rtLogFn, 0x14);

	log(skCrypt("[rwdrv] Realtek pointer location at [0x%p]\n"), PVOID(rtDataPtr));
	
	g::DriverState.OriginalSyscallFn =
		InterlockedExchangePointer(
			static_cast<PVOID volatile*>(syscallDataPtr),
			PVOID(rtDataPtr)
		);

	g::DriverState.OriginalWmiFn =
		InterlockedExchangePointer(
			static_cast<PVOID volatile*>(rtDataPtr),
			PVOID(HookControl)
		);
	
	log(skCrypt("[rwdrv] Successfully placed hooks\n"));

	return STATUS_SUCCESS;
}

bool CheckPEImage(PVOID imgBase)
{
	if (!imgBase)
	{
		return false;
	}

	auto* const pIdh = PIMAGE_DOS_HEADER(imgBase);

	if (pIdh->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return false;
	}

	auto* pInh = PIMAGE_NT_HEADERS(LPBYTE(imgBase) + pIdh->e_lfanew);

	if (pInh->Signature != IMAGE_NT_SIGNATURE)
	{
		return false;
	}

	if (pInh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
	{
		return false;
	}

	return true;
}


NTSTATUS InitRoutine(PVOID baseAddr, ULONG imageSize, PVOID kernelBase)
{
	g::DriverState.BaseAddress = baseAddr;
	g::DriverState.ImageSize = imageSize;

	const auto status = Search::SetKernelProps(kernelBase);
	if (!NT_SUCCESS(status))
	{
		log(skCrypt("[rwdrv] Failed to obtain kernel modules\n"));
	}

	return status;
}

NTSTATUS DriverEntry(PVOID baseAddress, ULONG imageSize, PVOID kernelBase)
{
	// Cannot use logging until g::KernelBase is set

	if (!CheckPEImage(kernelBase))
	{
		return STATUS_INVALID_PARAMETER;
	}
	g::KernelBase = kernelBase;

	log(skCrypt("[rwdrv] Driver loaded at [0x%p]\n"), baseAddress);

	auto status = InitRoutine(baseAddress, imageSize, kernelBase);
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
