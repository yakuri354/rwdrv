#include "clean.hpp"

PVOID Search::KernelBase = nullptr;
ULONG Search::KernelSize = 0;
PVOID Search::Win32kBase = nullptr;
ULONG Search::Win32kSize = 0;

NTSTATUS Search::SetKernelProps()
{
	ULONG bytes = 0;
	UNICODE_STRING routineName;

	// Already found
	if (KernelBase != nullptr && KernelSize != 0
		&& Win32kBase != nullptr && Win32kSize != 0)
	{
		return STATUS_SUCCESS;
	}

	RtlUnicodeStringInit(&routineName, skCrypt(L"NtOpenFile"));

	const auto checkPtr = MmGetSystemRoutineAddress(&routineName);
	if (checkPtr == nullptr)
		return STATUS_UNSUCCESSFUL;

	// Protect from UserMode AV
	auto status = ZwQuerySystemInformation(SystemModuleInformation, nullptr, bytes, &bytes);
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
	log(skCrypt("[rwdrv] KernelBase: [0x%p]\n"), KernelBase);
	log(skCrypt("[rwdrv] KernelSize: [%d]\n"), KernelSize);
	log(skCrypt("[rwdrv] Win32kBase: [0x%p]\n"), Win32kBase);
	log(skCrypt("[rwdrv] Win32kSize: [%d]\n"), Win32kSize);
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

NTSTATUS Search::BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base,
	IN ULONG_PTR size, OUT PVOID* ppFound, int index)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_ACCESS_DENIED; //STATUS_INVALID_PARAMETER;
	int cIndex = 0;
	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != static_cast<PCUCHAR>(base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE && cIndex++ == index)
		{
			*ppFound = PUCHAR(base) + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}

NTSTATUS Search::BBScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound, PVOID base)
{
	//ASSERT(ppFound != NULL);
	if (ppFound == nullptr)
		return STATUS_ACCESS_DENIED; //STATUS_INVALID_PARAMETER

	if (base == nullptr)
		base = KernelBase;

	PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
	if (!pHdr)
		return STATUS_ACCESS_DENIED; // STATUS_INVALID_IMAGE_FORMAT;

	//PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	PIMAGE_SECTION_HEADER pFirstSection = PIMAGE_SECTION_HEADER(uintptr_t(&pHdr->FileHeader) + pHdr
		->FileHeader.
		SizeOfOptionalHeader +
		sizeof(IMAGE_FILE_HEADER));

	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections;
		pSection++)
	{
		//DbgPrint("section: %s\r\n", pSection->Name);
		ANSI_STRING s1, s2;
		RtlInitAnsiString(&s1, section);
		RtlInitAnsiString(&s2, PCCHAR(pSection->Name));
		if (RtlCompareString(&s1, &s2, TRUE) == 0)
		{
			PVOID ptr = NULL;
			NTSTATUS status = BBSearchPattern(pattern, wildcard, len, PUCHAR(base) + pSection->VirtualAddress,
				pSection->Misc.VirtualSize, &ptr);
			if (NT_SUCCESS(status))
			{
				*PULONG64(ppFound) = ULONG_PTR(ptr); //- (PUCHAR)base
				//DbgPrint("found\r\n");
				return status;
			}
			//we continue scanning because there can be multiple sections with the same name.
		}
	}

	return STATUS_ACCESS_DENIED; //STATUS_NOT_FOUND;
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