#include "search.hpp"
#include "skcrypt.hpp"

#undef F_INLINE
#define F_INLINE

F_INLINE NTSTATUS Search::FindModules()
{
	ULONG bytes = 0;

	auto status = C_FN(ZwQuerySystemInformation)(SystemModuleInformation, nullptr, bytes, &bytes);
	if (!NT_SUCCESS(status))
	{
		log("ZwQuerySystemInformation failed with code 0x%x", status);
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
		log("ZwQuerySystemInformation failed with code 0x%x", status);
		return STATUS_UNSUCCESSFUL;
	}

	log("Searching through %d modules", pMods->NumberOfModules);

	bool win32k{}, realtek{}, cidll{}; // TODO Refactor

	constexpr auto wkHash = StrHash(R"(\SystemRoot\System32\win32kbase.sys)");
	constexpr auto rtHash = StrHash(R"(\SystemRoot\System32\drivers\rt640x64.sys)");
	constexpr auto ciHash = StrHash(R"(\SystemRoot\System32\ci.dll)");

	auto* const pMod = pMods->Modules;

	g::Kernel.Size = pMod->ImageSize;

	for (ULONG i = 1; i < pMods->NumberOfModules; i++)
	{
		switch (StrHash(PCHAR(pMod[i].FullPathName)))
		{
		case wkHash:
			g::Win32k.Base = pMod[i].ImageBase;
			g::Win32k.Size = pMod[i].ImageSize;
			win32k = true;
			break;
		case rtHash:
			g::Realtek.Base = pMod[i].ImageBase;
			g::Realtek.Size = pMod[i].ImageSize;
			realtek = true;
			break;
		case ciHash:
			g::CIdll.Base = pMod[i].ImageBase;
			g::CIdll.Size = pMod[i].ImageSize;
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

	log("Kernel  Base: [0x%p]", g::Kernel.Base);
	log("Win32k  Base: [0x%p]", g::Win32k.Base);
	log("Ci.dll  Base: [0x%p]", g::CIdll.Base);
	log("Realtek Base: [0x%p]", g::Realtek.Base);
	log("Realtek Size: [0x%x]", g::Realtek.Size);
	return STATUS_SUCCESS;
}

F_INLINE PVOID Search::RVA(
	_In_ UINT64 instruction,
	_In_ const ULONG offset
)
{
	const auto ripOffset = *PLONG(instruction + offset);

	return PVOID(instruction + offset + sizeof(LONG) + ripOffset);
}

F_INLINE PVOID Search::ResolveEnclosingSig(UINT64 callAddress, UINT movOffset)
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

F_INLINE UINT64 Search::FindPattern(UINT64 dwAddress, UINT64 dwLen, BYTE* bMask, char* szMask)
{
	for (UINT64 i = 0; i < dwLen; i++)
		if (bDataCompare(reinterpret_cast<BYTE*>(dwAddress + i), bMask, szMask))
			return UINT64(dwAddress + i);

	return 0;
}
