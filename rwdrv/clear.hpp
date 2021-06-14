#pragma once
#include <ntifs.h>
#define NO_DDK
#include "common.hpp"

namespace Clear
{
	NTSTATUS ClearSystemBigPoolInfo(PVOID pageAddr);
	// NTSTATUS SpoofDiskSerials(PVOID kernelBase, PDRIVER_DISPATCH* originalDispatchAddress);
	NTSTATUS ClearPfnEntry(PVOID pageAddress, ULONG pageSize);
	NTSTATUS ClearCiEaCache();
	NTSTATUS CleanupMiscTraces(DriverState* driverState);
}
