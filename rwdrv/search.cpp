#include "search.hpp"
#include "skcrypt.hpp"

char* strrchr_(const char* cp, const int ch)
{
	char* save;
	char c;

	for (save = nullptr; (c = *cp) != 0; cp++) {
		if (c == ch)
			save = PCHAR(cp);
	}

	return save;
}

NTSTATUS Search::FindModules()
{
	ULONG bytes = 0;

	auto status = C_FN(ZwQuerySystemInformation)(SystemModuleInformation, nullptr, bytes, &bytes);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		log("ZwQuerySystemInformation failed with code 0x%X", status);
		return STATUS_UNSUCCESSFUL;
	}

	auto* const pMods = static_cast<PRTL_PROCESS_MODULES>(C_FN(ExAllocatePoolWithTag)(
		NonPagedPool, bytes, BB_POOL_TAG));

	if (pMods == nullptr)
	{
		log("Alloc failed");
		return STATUS_UNSUCCESSFUL;
	}

	RtlZeroMemory(pMods, bytes);

	status = C_FN(ZwQuerySystemInformation)(SystemModuleInformation, pMods, bytes, &bytes);

	if (!NT_SUCCESS(status))
	{
		C_FN(ExFreePoolWithTag)(pMods, BB_POOL_TAG);
		log("ZwQuerySystemInformation failed with code 0x%X", status);
		return STATUS_UNSUCCESSFUL;
	}

	log("Searching through %d modules", pMods->NumberOfModules);

	bool win32k{}, realtek{}, cidll{}; // TODO Refactor

	constexpr auto wkHash = StrHash("win32kbase.sys");
	constexpr auto rtHash = StrHash("rt640x64.sys");
	constexpr auto ciHash = StrHash("CI.dll");

	auto* const pMod = pMods->Modules;

	for (ULONG i = 1; i < pMods->NumberOfModules; i++)
	{
		switch (StrHash(strrchr_(PCHAR(pMod[i].FullPathName), '\\') + 1))
		{
		case wkHash:
			g::Win32k = pMod[i].ImageBase;
			win32k = true;
			break;
		case rtHash:
			g::Realtek = pMod[i].ImageBase;
			realtek = true;
			break;
		case ciHash:
			g::CIdll = pMod[i].ImageBase;
			cidll = true;
			break;
		default:;
		}
	}

	C_FN(ExFreePoolWithTag)(pMods, BB_POOL_TAG);

	if (!win32k || !realtek | !cidll)
	{
		log("Could not find base addresses of modules; win32kbase: %d; rt640: %d, cidll: %d", win32k, realtek, cidll);
		return STATUS_NOT_FOUND;
	}

	log("Ntoskrnl at [0x%p]", g::Kernel);
	log("Win32k at [0x%p]", g::Win32k);
	log("CI.dll at [0x%p]", g::CIdll);
	log("rt640x64 at [0x%p]", g::Realtek);
	return STATUS_SUCCESS;
}

PVOID Search::RVA(
	_In_ UINT64 instruction,
	_In_ const ULONG offset
)
{
	const auto ripOffset = *PLONG(instruction + offset);

	return PVOID(instruction + offset + sizeof(LONG) + ripOffset);
}

PVOID Search::ResolveEnclosingSig(UINT64 callAddress, UINT movOffset)
{
	const auto targetFn = UINT64(RVA(callAddress, 1));
	return RVA(targetFn + movOffset, 3);
}


F_INLINE BOOLEAN Search::bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
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

UINT64 Search::FindPatternInSection(PVOID base, PCCHAR section, PUCHAR bMask, PCHAR szMask)
{
	ASSERT(ppFound != NULL);

	if (!base) return NULL;

	const auto pHdr = PIMAGE_NT_HEADERS(UINT_PTR(base) + PIMAGE_DOS_HEADER(base)->e_lfanew);
	
	if (!pHdr) return NULL;

	const auto pFirstSection = PIMAGE_SECTION_HEADER(pHdr + 1);
	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
	{
		if (strcmp(PCHAR(pSection->Name), section) == 0)
		{
			return FindPattern(UINT64(base) + pSection->VirtualAddress, pSection->Misc.VirtualSize, bMask, szMask);
		}
	}

	return NULL;
}