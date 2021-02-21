#pragma once
#include "common.hpp"

#define C_FN(name) (LazyFn<decltype(name)>(skCrypt(#name)))

template <typename Fn>
__forceinline Fn* LazyFn(const char* name)
{
	auto* const peHeader = PIMAGE_DOS_HEADER(g::KernelBase);

	auto* const ntHeader = PIMAGE_NT_HEADERS(UINT64(g::KernelBase) + peHeader->e_lfanew);

	auto* const imageExportDirectory = PIMAGE_EXPORT_DIRECTORY(
		UINT64(g::KernelBase) + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	auto* const address = PDWORD(UINT64(g::KernelBase) + imageExportDirectory->AddressOfFunctions);
	auto* const addressOfNames = PDWORD(UINT64(g::KernelBase) + imageExportDirectory->AddressOfNames);

	auto* const ordinal = PWORD(UINT64(g::KernelBase) + imageExportDirectory->AddressOfNameOrdinals);

	for (unsigned i = 0; i < imageExportDirectory->AddressOfFunctions; i++)
	{
		if (!strcmp(name, PCHAR(g::KernelBase) + addressOfNames[i]))
		{
			return reinterpret_cast<Fn*>(UINT64(g::KernelBase) + address[ordinal[i]]);
		}
	}
	return nullptr;
}

