#include "common.hpp"
#include "search.hpp"
#include "skcrypt.hpp"
#include "util.hpp"

PVOID Search::KernelBase = nullptr;
ULONG Search::KernelSize = 0;
PVOID Search::Win32kBase = nullptr;
ULONG Search::Win32kSize = 0;

NTSTATUS Search::SetKernelProps()
{
	NTSTATUS status;
	ULONG bytes = 0;

	// Already found
	if (KernelBase != nullptr && KernelSize != 0
		&& Win32kBase != nullptr && Win32kSize != 0)
	{
		return STATUS_SUCCESS;
	}
	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, skCrypt(L"NtOpenFile"));

	const auto checkPtr = MmGetSystemRoutineAddress(&routineName);
	if (checkPtr == nullptr)
		return STATUS_UNSUCCESSFUL;
	// Protect from UserMode AV
	status = ZwQuerySystemInformation(SystemModuleInformation, nullptr, bytes, &bytes);
	if (bytes == 0)
	{
		log(skCrypt("[rwdrv] Invalid SystemModuleInformation size\n"));
		return STATUS_UNSUCCESSFUL;
	}

	const auto pMods = static_cast<PRTL_PROCESS_MODULES>(ExAllocatePoolWithTag(
		NonPagedPool, bytes, BB_POOL_TAG));

	if (pMods == nullptr)
	{
		return STATUS_UNSUCCESSFUL;
	}

	RtlZeroMemory(pMods, bytes);

	status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

	log(skCrypt("[rwdrv] Searching trough %d modules\n"), pMods->NumberOfModules);

	// TODO Refactor module searching and make it less spaghetti

	auto kf = false, wf = false;

	if (NT_SUCCESS(status))
	{
		const auto pMod = pMods->Modules;

		for (ULONG i = 0; i < pMods->NumberOfModules; i++)
		{
			if (!kf) {
			
				// System routine is inside module
				if (checkPtr >= pMod[i].ImageBase &&
					checkPtr < PVOID(PUCHAR(pMod[i].ImageBase) + pMod[i].ImageSize))
				{
					KernelBase = pMod[i].ImageBase;
					KernelSize = pMod[i].ImageSize;
					kf = true;
					continue;
				}
			}
			if (!wf)
			{
				if (strcmp(reinterpret_cast<const char*>(pMod[i].FullPathName),
					skCrypt("\\SystemRoot\\System32\\win32kbase.sys")) == 0)
				{
					Win32kBase = pMod[i].ImageBase;
					Win32kSize = pMod[i].ImageSize;
					wf = true;
					continue;
				}
			}
			if (kf && wf)
			{
				break;
			}
		}
	}

	if (pMods) {
		ExFreePoolWithTag(pMods, BB_POOL_TAG);
	}

	if (!wf || !kf)
	{
		log(skCrypt("[rwdrv] Could not find base addresses of modules\n"));
		return STATUS_NOT_FOUND;
	}
	
	log(skCrypt("[rwdrv] KernelBase: [0x%p]\n"), KernelBase);
	//log(skCrypt("[rwdrv] KernelSize: [%d]\n"), KernelSize);
	log(skCrypt("[rwdrv] Win32kBase: [0x%p]\n"), Win32kBase);
	//log(skCrypt("[rwdrv] Win32kSize: [%d]\n"), Win32kSize);
	return STATUS_SUCCESS;
}

extern "C" PVOID Search::ResolveRelativeAddress(
	_In_ PVOID instruction,
	_In_ const ULONG OffsetOffset,
	_In_ ULONG instructionSize
)
{
	const auto instr = ULONG_PTR(instruction);
	const auto ripOffset = *PLONG(instr + OffsetOffset);
	const auto resolvedAddress = PVOID(instr + instructionSize + ripOffset);

	return resolvedAddress;
}


BOOLEAN Search::bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
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