#pragma once
#include "common.hpp"

namespace Search {
	extern PVOID KernelBase;
	extern ULONG KernelSize;
	extern PVOID Win32kBase;
	extern ULONG Win32kSize;
	extern PVOID CIBase;
	extern ULONG CISize;

	NTSTATUS SetKernelProps(PVOID kernelBase);
	extern "C" PVOID ResolveRelativeAddress(
		_In_ PVOID instruction,
		_In_ const ULONG OffsetOffset,
		_In_ ULONG instructionSize
	);
	NTSTATUS BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base,
		IN ULONG_PTR size, OUT PVOID* ppFound, int index = 0);
	NTSTATUS BBScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound,
		PVOID base = nullptr);
	BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
	UINT64 FindPattern(UINT64 dwAddress, UINT64 dwLen, BYTE* bMask, char* szMask);
}