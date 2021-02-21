#define NO_DDK
#include <ntifs.h>
#include "common.hpp"
#include "clean.hpp"
#include "search.hpp"
#include "util.hpp"
#include "skcrypt.hpp"
#include "comms.hpp"


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
	 SharedMemory;
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
			if (g::DriverState.SharedMemory.Va == nullptr)
			{
				LARGE_INTEGER ptr = {};

				ptr.LowPart = a2;
				ptr.HighPart = a3;

				log(skCrypt("[rwdrv] Init step 1; Setting shared memory Va to [%p]\n"), PVOID(ptr.QuadPart));

				g::DriverState.SharedMemory.Va = PVOID(ptr.QuadPart);

				return STATUS_SUCCESS;
			}
			if (g::DriverState.SharedMemory.Pid == 0)
			{
				log(skCrypt("[rwdrv] Init step 2; Setting shared memory PID (%u)\n"), a2);

				g::DriverState.SharedMemory.Pid = a2;
				auto status =
					PsLookupProcessByProcessId(
						HANDLE(a2),
						&g::DriverState.SharedMemory.Proc
					);

				if (!NT_SUCCESS(status))
				{
					log(skCrypt("[rwdrv] PsLookupByProcessId failed\n"));
					return status;
				}

				log(skCrypt("[rwdrv] Making probe write to address [%p]\n"), g::DriverState.SharedMemory.Va);
				
				if (MmIsAddressValid(g::DriverState.SharedMemory.Va))
				{
					*static_cast<unsigned*>(g::DriverState.SharedMemory.Va) = CTL_MAGIC;
				} else
				{
					log(skCrypt("[rwdrv] Bad shared memory Va\n"));
				}

				// log(skCrypt("Raw Address %d\n"), MmIsAddressValid(g::DriverState.SharedMemory.Va));
				//
				// char a = 0;
				//
				// SIZE_T bytesWritten{};
				//
				// log(skCrypt("MmCopyVirtualmemory %p %p %p %p %d UserMode %p\n"), PsGetCurrentProcess(), &a, g::DriverState.SharedMemory.Proc, g::DriverState.SharedMemory.Va, sizeof(char), &bytesWritten);
				//
				// if (!NT_SUCCESS(
				// 	status = MmCopyVirtualMemory(
				// 		PsGetCurrentProcess(),
				// 		&a, 
				// 		g::DriverState.SharedMemory.Proc,
				// 		g::DriverState.SharedMemory.Va, 
				// 		sizeof(char), 
				// 		UserMode,
				// 		&bytesWritten)
				// ))
				// {
				// 	log(skCrypt("[rwdrv] Probe write to shared memory failed\n"));
				// 	return status;
				// }

				return STATUS_SUCCESS;
			}

			log(skCrypt("[rwdrv] Init step 3; Cleaning up misc traces\n"));

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

	log(skCrypt("[rwdrv] Original function address: [0x%p]\n"), *reinterpret_cast<PVOID*>(fnPtrLocation));

	*reinterpret_cast<PVOID*>(&g::DriverState.OriginalHookedFn) = InterlockedExchangePointer(
		reinterpret_cast<PVOID*>(fnPtrLocation), PVOID(HookControl));

	log(skCrypt("[rwdrv] Successfully placed hook\n"));

	return STATUS_SUCCESS;
}


NTSTATUS InitRoutine(PVOID baseAddr, ULONG imageSize)
{
	g::DriverState.BaseAddress = baseAddr;
	g::DriverState.ImageSize = imageSize;

	const auto status = Search::SetKernelProps();
	if (!NT_SUCCESS(status))
	{
		log(skCrypt("[rwdrv] Failed to obtain kernel modules\n"));
	}

	return status;
}

NTSTATUS DriverEntry(PVOID baseAddress, ULONG imageSize)
{
	log(skCrypt("[rwdrv] Driver loaded at [0x%p]\n"), baseAddress);

	auto status = InitRoutine(baseAddress, imageSize);
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
