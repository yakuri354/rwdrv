#pragma once
#include "common.h"
#include "search.hpp"


namespace Clear
{
	NTSTATUS ClearSystemBigPoolInfo(PVOID64 pageAddr);
	NTSTATUS ClearPfnDatabase(); // TODO
	NTSTATUS SpoofDiskSerials();
}
