#define NO_DDK
#include <ntifs.h>
#include "common.hpp"
#include "clean.hpp"
#include "search.hpp"
#include "cache.hpp"
#include "util.hpp"
#include "skcrypt.hpp"
#include "comms.hpp"

PVOID g::KernelBase;

struct SharedMem
{
	PVOID Va;
};

struct _DriverState
{
	bool Initialized;
	PVOID BaseAddress;
	ULONG ImageSize;
	PHookFn HookControl;
	PHookFn OriginalHookedFn;
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

UINT __fastcall HookControl(UINT a1, UINT a2, UINT a3)
{
	log(skCrypt("[rwdrv] Hook called!, args [0x%X] [0x%X] [0x%X]\n"), a1, a2, a3);

	if (a1 == CTL_MAGIC)
	{
		if (!g::DriverState.Initialized)
		{
			LARGE_INTEGER ptr = {};

			ptr.LowPart = a2;
			ptr.HighPart = a3;

			log(skCrypt("[rwdrv] Initializing; Setting shared memory Va to [%p]\n"), PVOID(ptr.QuadPart));

			g::DriverState.SharedMemory = PVOID(ptr.QuadPart);

			log(skCrypt("[rwdrv] Testing shmem Va "));

			if (MmIsAddressValid(g::DriverState.SharedMemory))
			{
				*static_cast<unsigned*>(g::DriverState.SharedMemory) = CTL_MAGIC;
			}
			else
			{
				log(skCrypt("[rwdrv] Bad shared memory Va\n"));
			}

			log(skCrypt("[rwdrv] Cleaning up traces"));

			return CleanupMiscTraces();
		}
		// TODO Control codes
		// TODO Shared memory
		return STATUS_SUCCESS;
	}

	return g::DriverState.OriginalHookedFn(a1, a2, a3);
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

	const auto fnPtrLocation = Search::ResolveRelativeAddress(PVOID(movInstruction), 3, 7);

	log(skCrypt("[rwdrv] Function pointer location at [0x%p]\n"), PVOID(fnPtrLocation));

	log(skCrypt("[rwdrv] Original function address: [0x%p]\n"), *static_cast<PVOID*>(fnPtrLocation));

	*reinterpret_cast<PVOID*>(&g::DriverState.OriginalHookedFn) = InterlockedExchangePointer(
		static_cast<PVOID*>(fnPtrLocation), PVOID(HookControl));

	log(skCrypt("[rwdrv] Successfully placed hook\n"));

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
	if (!CheckPEImage(kernelBase))
	{
		log(skCrypt("[rwdrv] KernelBase invalid\n"));
		return STATUS_UNSUCCESSFUL;
	}
	
	g::KernelBase = kernelBase;

	const auto status = Search::SetKernelProps();
	if (!NT_SUCCESS(status))
	{
		log(skCrypt("[rwdrv] Failed to obtain kernel modules\n"));
	}

	return status;
}

NTSTATUS DriverEntry(PVOID baseAddress, ULONG imageSize, PVOID kernelBase)
{
	log(skCrypt("[rwdrv] Driver loaded at [0x%p]\n"), baseAddress);

	auto status = InitRoutine(baseAddress, imageSize, kernelBase);
	if (!NT_SUCCESS(status))
	{
		log(skCrypt("[rwdrv] Driver initialization routine failed.\n"));
		return status;
	}

	C_FN(DbgPrint)("Hello World!\n");
	
	status = SetupHook();
	if (!NT_SUCCESS(status))
	{
		log(skCrypt("[rwdrv] Failed to setup communication hook\n"));
		return status;
	}

	return status;
}
