#include "exec.hpp"

NTSTATUS InitDriver(UINT32 a1, UINT32 a2, DriverState* driverState);
NTSTATUS UnloadDriver(DriverState* state);
NTSTATUS ReadVirtualMemory(HANDLE pid, PVOID va, PVOID buffer, SIZE_T size, PSIZE_T bytesRead);
NTSTATUS WriteVirtualMemory(HANDLE pid, PVOID va, PVOID buffer, SIZE_T size, PSIZE_T bytesRead);

NTSTATUS ExecuteRequest(UINT32 ctlCode, UINT16 magic, UINT32 param, DriverState* driverState)
{
	SIZE_T bytes{};
	PVOID writeBuffer{};
	PVOID addr{};

	if (magic == INIT_MAGIC)
	{
		return InitDriver(ctlCode, param, driverState);
	}
	
	if (magic == CTL_MAGIC)
		switch (ctlCode)
		{
		case Ctl::PING:
			log("Ping received");
			return STATUS_SUCCESS;

		case Ctl::STATUS: // TODO Status bitmask
			log("Status requested");
			return driverState->Initialized ? 1 : 0;

		case Ctl::UNLOAD:
			log("Unloading driver");
			return UnloadDriver(driverState);

		case Ctl::SET_TARGET:
			log("Target set to %u", param);
			driverState->TargetProcess = HANDLE(param);
			return STATUS_SUCCESS;

		case Ctl::GET_BASE_ADDR:
			log("Getting base address of process %u", param);
			return GetProcessBase(driverState->TargetProcess, static_cast<PVOID*>(driverState->SharedMemory));

		case Ctl::READ_PHYSICAL:
			addr = *static_cast<PVOID*>(driverState->SharedMemory);
			return Phys::ReadPhysicalAddress(addr, driverState->SharedMemory, SIZE_T(param), &bytes);

		case Ctl::WRITE_PHYSICAL:
			addr = *static_cast<PVOID*>(driverState->SharedMemory);
			writeBuffer = PVOID(UINT64(driverState->SharedMemory) + sizeof(PVOID));
			return Phys::WritePhysicalAddress(addr, writeBuffer, SIZE_T(param), &bytes);

		case Ctl::READ_VIRTUAL:
			addr = *static_cast<PVOID*>(driverState->SharedMemory);
#if USE_PHYSMEM
			return Phys::ReadProcessMemory(driverState->TargetProcess, addr, driverState->SharedMemory, SIZE_T(param), &bytes);
#else
			return ReadVirtualMemory(driverState->TargetProcess, addr, driverState->SharedMemory, SIZE_T(param), &bytes);
#endif

		case Ctl::WRITE_VIRTUAL:
			addr = *static_cast<PVOID*>(driverState->SharedMemory);
			writeBuffer = PVOID(UINT64(driverState->SharedMemory) + sizeof(PVOID));
#if USE_PHYSMEM
			return Phys::WriteProcessMemory(driverState->TargetProcess, addr, writeBuffer, SIZE_T(param), &bytes);
#else
			return WriteVirtualMemory(driverState->TargetProcess, addr, writeBuffer, SIZE_T(param), &bytes);
#endif
		default:
			log("Invalid ctlCode received: 0x%x", ctlCode);
			return STATUS_INVALID_PARAMETER;
		}
	
	ASSERT((false /* This should not be reached */));
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS InitDriver(UINT32 a1, UINT32 a2, DriverState* driverState)
{
	LARGE_INTEGER lint{};
	lint.LowPart = UINT32(a1);
	lint.HighPart = UINT32(a2);

	log("Initializing; Shared memory at [%p]", PVOID(lint.QuadPart));

	dbgLog("CR3 [0x%llx]", __readcr3());

	if (lint.QuadPart && C_FN(MmIsAddressValid)(PVOID(lint.QuadPart)))
	{
		*PUINT16(lint.QuadPart) = INIT_MAGIC;
	}
	else
	{
		log("Bad shared memory Va");
		return STATUS_UNSUCCESSFUL;
	}

	driverState->SharedMemory = PVOID(lint.QuadPart);

	if (!driverState->Initialized) {
		
		log("First init call; Cleaning up traces");

		const auto status = Clear::CleanupMiscTraces(driverState);

		if (!NT_SUCCESS(status))
		{
			log("Cleaning traces failed, aborting");
			return STATUS_UNSUCCESSFUL;
		}

		log("Driver successfully initialized");
		driverState->Initialized = true;
	}
	else log("Traces already cleaned, continuing");

	return STATUS_SUCCESS;
}

NTSTATUS ReadVirtualMemory(HANDLE pid, PVOID va, PVOID buffer, SIZE_T size, PSIZE_T bytesRead)
{
	PEPROCESS proc;
	
	if (!NT_SUCCESS(C_FN(PsLookupProcessByProcessId)(pid, &proc))) {
		log("Process %llu not found", UINT64(pid));
		return STATUS_NOT_FOUND;
	}

	const auto status = C_FN(MmCopyVirtualMemory)(
		proc,
		va,
		C_FN(IoGetCurrentProcess)(),
		buffer,
		size,
		UserMode,
		bytesRead
		);

	C_FN(ObfDereferenceObject)(proc);

	if (!NT_SUCCESS(status)) log("Va read at [0x%p] failed with status 0x%x", va, status);

	return status;
}

NTSTATUS WriteVirtualMemory(HANDLE pid, PVOID va, PVOID buffer, SIZE_T size, PSIZE_T bytesRead)
{
	PEPROCESS proc;
	if (!NT_SUCCESS(C_FN(PsLookupProcessByProcessId)(pid, &proc))) {
		log("Process %llu not found", UINT64(pid));
		return STATUS_NOT_FOUND;
	}

	const auto status = C_FN(MmCopyVirtualMemory)(
		C_FN(IoGetCurrentProcess)(),
		buffer,
		proc,
		va,
		size,
		UserMode,
		bytesRead
		);

	C_FN(ObfDereferenceObject)(proc);

	if (!NT_SUCCESS(status)) log("Va write at [0x%p] failed with status 0x%x", va, status);

	return status;
}

NTSTATUS UnloadDriver(DriverState* state)
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
