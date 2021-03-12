#define NO_DDK
#include <ntifs.h>
#include "common.hpp"
#include "clear.hpp"
#include "search.hpp"
#include "util.hpp"
#include "skcrypt.hpp"
#include "comms.hpp"
#include "intrin.h"
#include "exec.hpp"


PVOID g::KernelBase;

namespace g
{
	::DriverState DriverState{};
}

UINT64 __fastcall HookControl(UINT64 ctlCode, UINT64 a2, UINT64 param, UINT16 magic, UINT64 a5)
{
	if (magic == CTL_MAGIC)
	{
		return NT2CTL(ExecuteRequest(UINT32(ctlCode), UINT32(param), &g::DriverState));
	}

	if (ctlCode >= 0xffff000000000000u)
	{
		return _WmiTraceMessage(g::DriverState.Wmi.OrigPtr)(ctlCode, a2, param, magic, a5);
	}

	return PHookFn(g::DriverState.Syscall.OrigPtr)(UINT32(ctlCode), magic, UINT32(param));
}


NTSTATUS SetupHook()
{
	// The outside function, first in the chain
	// __int64 __fastcall ApiSetEditionOpenInputDesktopEntryPoint(unsigned int a1, unsigned int a2, unsigned int a3)
	const auto syscall = Search::FindPattern(
		UINT64(Search::Win32kBase),
		Search::Win32kSize,
		PUCHAR(PCHAR(skCrypt("\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x10\x44\x8B\xC7\x8B\xD6\x8B\xCD"))),
		skCrypt("xxx????xxxxxxxxxxxx")
	);

	if (syscall == NULL)
	{
		log(skCrypt("[rwdrv] Failed to locate syscall\n"));
		return STATUS_UNSUCCESSFUL;
	}

	auto* const syscallDataPtr = Search::RVA(syscall, 3);

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

	g::DriverState.Syscall.OrigPtr =
		InterlockedExchangePointer(
			static_cast<PVOID volatile*>(syscallDataPtr),
			Search::RVA(rtLogFn, 1)
		);

	g::DriverState.Wmi.OrigPtr =
		InterlockedExchangePointer(
			static_cast<PVOID volatile*>(rtDataPtr),
			PVOID(HookControl)
		);

	g::DriverState.Syscall.PtrLoc = PUINT64(syscallDataPtr);
	g::DriverState.Wmi.PtrLoc = PUINT64(rtDataPtr);
	
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
