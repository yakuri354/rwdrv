#pragma once
#include <ntifs.h>
#define NO_DDK
#include "common.hpp"

// TODO Great refactor of pasted code

namespace Clear
{
	NTSTATUS ClearSystemBigPoolInfo(PVOID pageAddr);
	NTSTATUS SpoofDiskSerials(PVOID kernelBase, PDRIVER_DISPATCH* originalDispatchAddress);
	NTSTATUS ClearPfnEntry(PVOID pageAddress, ULONG pageSize);
	NTSTATUS CleanupMiscTraces(DriverState* driverState);
}
