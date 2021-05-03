#pragma once
#define NO_DDK
#include <ntifs.h>
#include "common.hpp"

F_INLINE NTSTATUS GetProcessBase(HANDLE pid, OUT PVOID *address)
{
	PEPROCESS proc;

	const auto status = C_FN(PsLookupProcessByProcessId)(pid, &proc);
	
	if (!NT_SUCCESS(status))
	{
		log("Could not find process");
		return STATUS_NOT_FOUND;
	}

	const auto va = C_FN(PsGetProcessSectionBaseAddress)(proc);

	if (!va)
	{
		log("Could not find base");
		return STATUS_UNSUCCESSFUL;
	}

	*address = PVOID(va);

	return STATUS_SUCCESS;
}