#pragma once
#include "common.hpp"

namespace Search
{
	NTSTATUS FindModules();
	PVOID RVA(
		_In_ UINT64 instruction,
		_In_ const ULONG offset
	);

	PVOID ResolveEnclosingSig(
		UINT64 callAddress,
		UINT movOffset
	);

	inline BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
	UINT64 FindPattern(UINT64 dwAddress, UINT64 dwLen, BYTE* bMask, char* szMask);
}
