#include "common.hpp"
#include "search.hpp"
#include "skcrypt.hpp"
#include "util.hpp"

PVOID Search::KernelBase = nullptr;
ULONG Search::KernelSize = 0;
PVOID Search::Win32kBase = nullptr;
ULONG Search::Win32kSize = 0;
PVOID Search::RtBase = nullptr;
ULONG Search::RtSize = 0;

NTSTATUS Search::SetKernelProps(PVOID kernelBase)
{
	ULONG bytes = 0;

	if (KernelBase != nullptr && KernelSize != 0
		&& Win32kBase != nullptr && Win32kSize != 0)
	{
		return STATUS_SUCCESS;
	}

	auto status = C_FN(ZwQuerySystemInformation)(SystemModuleInformation, nullptr, bytes, &bytes);
	if (bytes == 0)
	{
		log(skCrypt("[rwdrv] Invalid SystemModuleInformation size\n"));
		return STATUS_UNSUCCESSFUL;
	}

	auto* const pMods = static_cast<PRTL_PROCESS_MODULES>(C_FN(ExAllocatePoolWithTag)(
		NonPagedPool, bytes, BB_POOL_TAG));

	if (pMods == nullptr)
	{
		return STATUS_UNSUCCESSFUL;
	}

	RtlZeroMemory(pMods, bytes);

	status = C_FN(ZwQuerySystemInformation)(SystemModuleInformation, pMods, bytes, &bytes);

	log(skCrypt("[rwdrv] Searching trough %d modules\n"), pMods->NumberOfModules);

	auto kf = false, wf = false, rf = false; // TODO Refactor & implement hashing

	if (NT_SUCCESS(status))
	{
		auto* const pMod = pMods->Modules;

		for (ULONG i = 0; i < pMods->NumberOfModules; i++)
		{
			if (!kf)
			{
				if (pMod[i].ImageBase == kernelBase)
				{
					KernelBase = pMod[i].ImageBase;
					KernelSize = pMod[i].ImageSize;
					kf = true;
					continue;
				}
			}
			if (!wf)
			{
				if (strcmp(PCHAR(pMod[i].FullPathName),
				           skCrypt("\\SystemRoot\\System32\\win32kbase.sys")) == 0)
				{
					Win32kBase = pMod[i].ImageBase;
					Win32kSize = pMod[i].ImageSize;
					wf = true;
					continue;
				}
			}
			if (!rf)
			{
				if (strcmp(PCHAR(pMod[i].FullPathName),
				           skCrypt("\\SystemRoot\\System32\\drivers\\rt640x64.sys")) == 0)
				{
					DbgBreakPoint();
					RtBase = pMod[i].ImageBase; // TODO fix
					RtSize = pMod[i].ImageSize;
					// The system module ranges are invalid
					rf = true;
					continue;
				}
			}
			if (kf && wf && rf)
			{
				break;
			}
		}
	}

	if (pMods)
	{
		C_FN(ExFreePoolWithTag)(pMods, BB_POOL_TAG);
	}
	
	if (!wf || !kf || !rf)
	{
		log(skCrypt("[rwdrv] Could not find base addresses of modules; kernel: %d; win32kbase: %d; rt640: %d\n"), kf, wf, rf);
		return STATUS_NOT_FOUND;
	}

	log(skCrypt("[rwdrv] KernelBase: [0x%p]\n"), KernelBase);
	log(skCrypt("[rwdrv] Win32kBase: [0x%p]\n"), Win32kBase);
	log(skCrypt("[rwdrv] RtBase: [0x%p]\n"), RtBase);
	log(skCrypt("[rwdrv] RtSize: [0x%x]\n"), RtSize);
	return STATUS_SUCCESS;
}

PVOID Search::ResolveRelativeAddress(
	_In_ UINT64 instruction,
	_In_ const ULONG OffsetOffset,
	_In_ ULONG instructionSize
)
{
	const auto ripOffset = *PLONG(instruction + OffsetOffset);
	auto* const resolvedAddress = PVOID(instruction + instructionSize + ripOffset);

	return resolvedAddress;
}

PVOID Search::ResolveEnclosingSig(UINT64 callAddress, UINT movOffset)
{
	const auto targetFn = UINT64(Search::ResolveRelativeAddress(callAddress, 1, 5));
	DbgBreakPoint();
	return Search::ResolveRelativeAddress(targetFn + movOffset, 3, 7);
}


inline BOOLEAN Search::bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return 0;

	return (*szMask) == 0;
}

UINT64 Search::FindPattern(UINT64 dwAddress, UINT64 dwLen, BYTE* bMask, char* szMask)
{
	for (UINT64 i = 0; i < dwLen; i++)
		if (bDataCompare(reinterpret_cast<BYTE*>(dwAddress + i), bMask, szMask))
			return UINT64(dwAddress + i);

	return 0;
}
