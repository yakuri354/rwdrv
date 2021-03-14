#include "exec.hpp"

NTSTATUS InitDriver(UINT32 a1, UINT32 a2, DriverState* driverState);
NTSTATUS UnloadDriver(DriverState* state);

NTSTATUS ExecuteRequest(UINT32 ctlCode, UINT16 magic, UINT32 param, DriverState* driverState)
{
	PEPROCESS proc{};
	NTSTATUS status;
	SIZE_T bytes{};
	PVOID pa;
	PVOID va;

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
			status = C_FN(PsLookupProcessByProcessId)(HANDLE(param), &proc);
			if (!NT_SUCCESS(status))
			{
				log("Could not find process");
				return STATUS_NOT_FOUND;
			}

			KeAttachProcess(proc);
			va = C_FN(PsGetProcessSectionBaseAddress)(proc);
			KeDetachProcess();

			if (!va)
			{
				log("Could not find base");
				return STATUS_UNSUCCESSFUL;
			}

			*PUINT64(driverState->SharedMemory) = UINT64(va);

			return STATUS_SUCCESS;

		case Ctl::READ_PHYS_MEM:
			pa = *static_cast<PVOID*>(driverState->SharedMemory);
			return Phys::ReadPhysicalAddress(pa, driverState->SharedMemory, SIZE_T(param), &bytes);

		case Ctl::WRITE_PHYS_MEM:
			pa = *static_cast<PVOID*>(driverState->SharedMemory);
			return Phys::WritePhysicalAddress(pa, driverState->SharedMemory, SIZE_T(param), &bytes);

		case Ctl::READ_TARGET_MEM:
			if (!NT_SUCCESS(C_FN(PsLookupProcessByProcessId)(driverState->TargetProcess, &proc))) return
				STATUS_NOT_FOUND;

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
			
			if (!NT_SUCCESS(status)) log("Va read at [0x%p] failed with status 0x%x", va, status);

			return status;

		case Ctl::WRITE_TARGET_MEM:
			if (!NT_SUCCESS(C_FN(PsLookupProcessByProcessId)(driverState->TargetProcess, &proc))) return
				STATUS_NOT_FOUND;

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

			if (!NT_SUCCESS(status)) log("Va write at [0x%p] failed with status 0x%x", va, status);

			return status;

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
