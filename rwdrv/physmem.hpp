#pragma once
#include <ntifs.h>
#include "common.hpp"

namespace Phys
{
	ULONG_PTR GetKernelDirBase();
	NTSTATUS ReadVirtual(UINT64 dirbase, UINT64 address, char* buffer, SIZE_T size, SIZE_T* read);
	NTSTATUS WriteVirtual(UINT64 dirbase, UINT64 address, char* buffer, SIZE_T size, SIZE_T* written);
	NTSTATUS ReadPhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead);
	NTSTATUS WritePhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten);
	NTSTATUS ReadProcessMemory(int pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* read);
	UINT64 TranslateLinearAddress(UINT64 directoryTableBase, UINT64 virtualAddress);
}
