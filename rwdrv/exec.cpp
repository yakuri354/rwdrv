#include "exec.hpp"

NTSTATUS InitDriver(UINT32 a1, UINT32 a2, DriverState* driverState);
NTSTATUS UnloadDriver(DriverState *state);

NTSTATUS ExecuteRequest(UINT32 ctlCode, UINT32 param, DriverState* driverState)
{
	PEPROCESS proc{};
	NTSTATUS status;
	SIZE_T bytes{};
	PVOID pa;
	PVOID va;

	if (!driverState->Initialized) // TODO Status before init
	{
		return InitDriver(ctlCode, param, driverState);
	}

	switch (ctlCode)
	{
	case Ctl::PING:
		log(skCrypt("[rwdrv] Ping received\n"));
		return STATUS_SUCCESS;

	case Ctl::STATUS: // TODO Status bitmask
		log(skCrypt("[rwdrv] Status requested\n"));
		return driverState->Initialized ? 1 : 0;

	case Ctl::UNLOAD:
		log(skCrypt("[rwdrv] Unloading driver\n"));
		return UnloadDriver(driverState);
		
	case Ctl::SET_TARGET:
		driverState->TargetProcess = HANDLE(param);
		return STATUS_SUCCESS;

	case Ctl::READ_PHYS_MEM:
		pa = *static_cast<PVOID*>(driverState->SharedMemory);
		return Phys::ReadPhysicalAddress(pa, driverState->SharedMemory, SIZE_T(param), &bytes);

	case Ctl::WRITE_PHYS_MEM:
		pa = *static_cast<PVOID*>(driverState->SharedMemory);
		return Phys::WritePhysicalAddress(pa, driverState->SharedMemory, SIZE_T(param), &bytes);

	case Ctl::READ_TARGET_MEM:
		if (!NT_SUCCESS(C_FN(PsLookupProcessByProcessId)(driverState->TargetProcess, &proc))) return STATUS_NOT_FOUND;

		va = *static_cast<PVOID*>(driverState->SharedMemory);

		status = C_FN(MmCopyVirtualMemory)(
			proc,
			va,
			C_FN(IoGetCurrentProcess)(),
			driverState->SharedMemory,
			param,
			UserMode,
			&bytes
		);

		C_FN(ObfDereferenceObject)(proc);

		return status;

	case Ctl::WRITE_TARGET_MEM:
		if (!NT_SUCCESS(C_FN(PsLookupProcessByProcessId)(driverState->TargetProcess, &proc))) return STATUS_NOT_FOUND;

		va = *reinterpret_cast<PVOID*>(UINT64(driverState->SharedMemory) + 8);

		status = C_FN(MmCopyVirtualMemory)(
			C_FN(IoGetCurrentProcess)(),
			driverState->SharedMemory,
			proc,
			va,
			param,
			UserMode,
			&bytes
		);

		C_FN(ObfDereferenceObject)(proc);
		
		return status;

	default:
		return STATUS_INVALID_PARAMETER;
	}
}

NTSTATUS InitDriver(UINT32 a1, UINT32 a2, DriverState* driverState)
{
	LARGE_INTEGER lint{};
	lint.LowPart = UINT32(a1);
	lint.HighPart = UINT32(a2);

	log(skCrypt("[rwdrv] Initializing; Shared memory at [%p]\n"), PVOID(lint.QuadPart));

	dbgLog(skCrypt("[rwdrv] CR3 [0x%p]\n"), __readcr3());

	if (lint.QuadPart && C_FN(MmIsAddressValid)(PVOID(lint.QuadPart)))
	{
		*PUINT16(lint.QuadPart) = CTL_MAGIC;
	}
	else
	{
		log(skCrypt("[rwdrv] Bad shared memory Va\n"));
		return STATUS_UNSUCCESSFUL; // TODO Specific status
	}

	driverState->SharedMemory = PVOID(lint.QuadPart);

	log(skCrypt("[rwdrv] Cleaning up traces\n"));

	const auto status = Clear::CleanupMiscTraces(driverState);

	if (!NT_SUCCESS(status))
	{
		log(skCrypt("[rwdrv] Cleaning traces failed, aborting\n"));
		return STATUS_UNSUCCESSFUL; // TODO Specific status
	}

	log(skCrypt("[rwdrv] Driver successfully initialized\n"));
	driverState->Initialized = true;

	return STATUS_SUCCESS;
}

NTSTATUS UnloadDriver(DriverState *state)
{
	InterlockedExchangePointer(
		reinterpret_cast<volatile PVOID*>(state->Syscall.PtrLoc),
		state->Syscall.OrigPtr
	);
	
	InterlockedExchangePointer(
		reinterpret_cast<volatile PVOID*>(state->Wmi.PtrLoc),
		state->Wmi.OrigPtr
	);

	return STATUS_SUCCESS;
}