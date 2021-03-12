#pragma once
#include "common.hpp"
#ifdef DEBUG
#define C_FN(name) name
#else
#ifdef IMPORT_NO_CACHE
#define C_FN(name) (LazyFn<decltype(name), hash_string(#name)>())
#else
#define C_FN(name) (LazyFnCached<decltype(name), hash_string(#name)>())
#endif
#endif

constexpr char inits[] = __TIME__;

constexpr UINT32 seedBase = (inits[0] - '0') * 100000 + (inits[1] - '0') * 10000 + (inits[3] - '0') * 1000 + (inits[4] -
	'0') * 100 + (inits[6] - '0') * 10 + inits[7] - '0';

constexpr UINT32 hash_string(const char* s)
{
	UINT32 hash = 0;

	for (; *s; ++s)
	{
		hash += *s;
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash;
}

template <typename Fn, UINT32 Hash>
#ifndef DEBUG
__forceinline
#endif
Fn* LazyFn()
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
		if (hash_string(PCHAR(g::KernelBase) + addressOfNames[i]) == Hash)
		{
			return reinterpret_cast<Fn*>(UINT64(g::KernelBase) + address[ordinal[i]]);
		}
	}
	return nullptr;
}

template <typename Fn, UINT32 Hash>
#ifndef DEBUG
__forceinline
#endif
Fn* LazyFnCached()
{
	static void* cache = nullptr;
	
	if (cache == nullptr) {
		auto ptr = LazyFn<Fn, Hash>();
		cache = PVOID(UINT64(ptr) ^ (UINT64(Hash) << 32 | UINT64(seedBase)));
		return ptr;
	}

	return reinterpret_cast<Fn*>(UINT64(cache) ^ (UINT64(Hash) << 32 | UINT64(seedBase)));
}
