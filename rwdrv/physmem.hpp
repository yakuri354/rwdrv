#pragma once
#include <ntifs.h>
#include "common.hpp"
#include "util.hpp"

//https://ntdiff.github.io/
#define WINDOWS_1803 17134
#define WINDOWS_1809 17763
#define WINDOWS_1903 18362
#define WINDOWS_1909 18363
#define WINDOWS_2004 19041
#define WINDOWS_20H2 19569
#define WINDOWS_21H1 20180


namespace Phys
{
	NTSTATUS ReadVirtual(UINT64 dirbase, UINT64 address, BYTE* buffer, SIZE_T size, SIZE_T* read);
	NTSTATUS WriteVirtual(UINT64 dirbase, UINT64 address, BYTE* buffer, SIZE_T size, SIZE_T* written);
	NTSTATUS ReadPhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead);
	NTSTATUS WritePhysicalAddress(PVOID targetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten);
	NTSTATUS ReadProcessMemory(HANDLE pid, PVOID va, PVOID buffer, SIZE_T size, SIZE_T* read);
	NTSTATUS WriteProcessMemory(HANDLE pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* written);
}