#pragma once
#include "config.hpp"
#ifdef DEBUG
#define C_FN(name) name
#else
#ifdef IMPORT_NO_CACHE
#define C_FN(name) (LazyFn<decltype(name), StrHash(#name)>())
#else
#define C_FN(name) (LazyFnCached<decltype(name), StrHash(#name)>())
#endif
#endif

constexpr auto TSeed = __TIME__;

constexpr auto Seed()
{
	UINT64 d = 0;

	for (auto k = TSeed; *k; ++k)
	{
		d ^= (d << 5) +
			(d >> 2) + *k;
	}

	return d * 13 + 2904521;
}

constexpr UINT64 Prng(UINT64 seed)
{
	const UINT64 s = seed * 6364136223846793005ULL + (seed | 1);
	const auto x = UINT32(((s >> 18u) ^ s) >> 27u);
	const UINT32 r = s >> 59u;
	return (x >> r | x << (UINT32(-INT32(r)) & 31)) ^ seed;
}

constexpr unsigned StrHash(const char* key)
{
	UINT32 hashVal = 0;
	constexpr auto s = Prng(Seed());
	
	for (; *key; ++key)
	{
		hashVal ^= (hashVal << 5) +
			(hashVal >> 2) + *key;
	}

	return UINT32(hashVal * s ^ Prng(s));
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
	
	for (unsigned i = 0; imageExportDirectory->AddressOfNames + (i * 4) < imageExportDirectory->AddressOfNameOrdinals; i++)
	{
		auto const key = PCHAR(g::KernelBase) + addressOfNames[i];
		if (StrHash(key) == Hash)
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
	constexpr auto s = Prng(Seed() + Hash);
	if (cache == nullptr) {
		auto ptr = LazyFn<Fn, Hash>();
		cache = PVOID(UINT64(ptr) ^ ((UINT64(Hash) << 32 | Hash) ^ s));
		return ptr;
	}

	return reinterpret_cast<Fn*>(UINT64(cache) ^ ((UINT64(Hash) << 32 | Hash) ^ s));
}
