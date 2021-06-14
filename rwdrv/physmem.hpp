#pragma once
#include <ntifs.h>
#include "common.hpp"
#include "util.hpp"

namespace Phys
{
	NTSTATUS ReadVirtual(UINT64 dirbase, UINT64 address, BYTE* buffer, SIZE_T size, SIZE_T* read);
	NTSTATUS WriteVirtual(UINT64 dirbase, UINT64 address, BYTE* buffer, SIZE_T size, SIZE_T* written);
	NTSTATUS ReadPhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead);
	NTSTATUS WritePhysicalAddress(PVOID targetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten);
	NTSTATUS ReadProcessMemory(HANDLE pid, PVOID va, PVOID buffer, SIZE_T size, SIZE_T* read);
	NTSTATUS WriteProcessMemory(HANDLE pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* written);
}