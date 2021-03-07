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

inline NTSTATUS CleanupMiscTraces()
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

UINT64 __fastcall HookControl(UINT64 ctlCode, UINT64 a2, UINT64 param, UINT16 magic, UINT64 a5) // TODO Move init logic to another function or file
{
	// log(skCrypt("[rwdrv] Hook called!, args [0x%p] [0x%p] [0x%p] [0x%xs] [0x%p]\n"), PVOID(ctlCode), PVOID(a2), PVOID(param), magic, PVOID(a5));

	__debugbreak();
	
	if (!g::DriverState.Initialized && magic == CTL_MAGIC)
	{	
		LARGE_INTEGER lint;
		lint.LowPart = UINT32(ctlCode);
		lint.HighPart = UINT32(param);

		log(skCrypt("[rwdrv] Initializing; Shared memory at [%p]\n"), PVOID(lint.QuadPart));
		
		log(skCrypt("[rwdrv] CR3 [0x%p]\n"), __readcr3());

		__debugbreak();

		if (C_FN(MmIsAddressValid)(PVOID(lint.QuadPart)))
		{
			*PUINT16(g::DriverState.SharedMemory) = CTL_MAGIC;
		}
		else
		{
			log(skCrypt("[rwdrv] Bad shared memory Va\n"));
			return CTL_GENERIC_ERROR; // TODO Specific status
		}
		
		g::DriverState.SharedMemory = PVOID(lint.QuadPart);
		
		log(skCrypt("[rwdrv] Cleaning up traces\n"));

		const auto status = CleanupMiscTraces();
		
		if (!NT_SUCCESS(status))
		{
			log(skCrypt("[rwdrv] Cleaning traces failed, aborting\n"));
			return CTL_GENERIC_ERROR; // TODO Specific status
		}
		
		log(skCrypt("[rwdrv] Driver successfully initialized\n"));
		g::DriverState.Initialized = true;
		
		return CTL_SUCCESS;
	}

	if (UINT16(magic) == CTL_MAGIC)
	{
		log(skCrypt("[rwdrv] Ctl called, code [%x]\n"), UINT32(ctlCode));
		// TODO Control codes
		// TODO Shared memory
		return CTL_SUCCESS;
	}

	if (magic > 1) // TODO More precise ways to detect Wmi call
	{
		log(skCrypt("[rwdrv] Restoring Wmi call\n"));
		return _WmiTraceMessage(g::DriverState.OriginalWmiFn)(ctlCode, a2, param, magic, a5);
	}
	
	log(skCrypt("[rwdrv] Restoring syscall: [0x%p] [0x%x]\n"), PVOID(ctlCode), UINT32(magic));
	return PHookFn(g::DriverState.OriginalSyscallFn)(UINT32(ctlCode), magic, UINT32(param));
}


NTSTATUS SetupHook()
{
	// The outside function, first in the chain
	// __int64 __fastcall ApiSetEditionOpenInputDesktopEntryPoint(unsigned int a1, unsigned int a2, unsigned int a3)
	auto syscall = Search::FindPattern(
		UINT64(Search::Win32kBase),
		Search::Win32kSize,
		PUCHAR(PCHAR(skCrypt("\x0F\x85\x00\x00\x00\x00\x48\x8B\x05\x00\x00\x00\x00\x49\x8B\xDE"))),
		skCrypt("xx????xxx????xxx")
	);

	if (syscall == NULL)
	{
		log(skCrypt("[rwdrv] Failed to locate syscall\n"));
		return STATUS_UNSUCCESSFUL;
	}

	syscall += 6; // Skip opcode due to sig
	
	auto* const syscallDataPtr = Search::ResolveRelativeAddress(syscall, 3);

	log(skCrypt("[rwdrv] Syscall pointer location at [0x%p]\n"), PVOID(syscallDataPtr));

	const auto rtLogFn = Search::FindPattern(
		UINT64(Search::RtBase),
		Search::RtSize,
		PUCHAR(PCHAR(skCrypt("\xE8\x00\x00\x00\x00\x4C\x8D\x5C\x24\x70\x8B\xC3"))),
		skCrypt("x????xxxxxxx")
	);

	if (rtLogFn == NULL)
	{
		log(skCrypt("[rwdrv] Failed to locate realtek log function\n"));
		return STATUS_UNSUCCESSFUL;
	}
	
	auto* const rtDataPtr = Search::ResolveEnclosingSig(rtLogFn, 0x18);

	log(skCrypt("[rwdrv] Realtek pointer location at [0x%p]\n"), PVOID(rtDataPtr));
	
	g::DriverState.OriginalSyscallFn =
		InterlockedExchangePointer(
			static_cast<PVOID volatile*>(syscallDataPtr),
			Search::ResolveRelativeAddress(rtLogFn, 1)
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
