#include "exec.hpp"

NTSTATUS UnloadDriver(DriverState* state);
NTSTATUS ReadVirtualMemory(HANDLE pid, PVOID va, PVOID buffer, SIZE_T size, PSIZE_T bytesRead);
NTSTATUS WriteVirtualMemory(HANDLE pid, PVOID va, PVOID buffer, SIZE_T size, PSIZE_T bytesRead);

NTSTATUS ExecuteRequest(Control* ctl, DriverState* driverState)
{
	switch (ctl->CtlCode)
	{
	case Ctl::PING:
		log("Ping received");
		return STATUS_SUCCESS;

	case Ctl::UNLOAD:
		log("Unloading driver");
		return UnloadDriver(driverState);

	case Ctl::CLEAN:
		if (driverState->TracesCleaned)
		{
			log("Traces already cleaned, proceeding");
			return STATUS_SUCCESS;
		}
		log("Cleaning traces");
		return Clear::CleanupMiscTraces(driverState);

	case Ctl::GET_BASE_ADDR:
		log("Getting base address of process %u", ctl->Pid);
		return GetProcessBase(HANDLE(ctl->Pid), reinterpret_cast<PVOID*>(&ctl->Result));

	case Ctl::PHYS_MEMCPY:
		return C_FN(MmCopyMemory)(ctl->Target, *reinterpret_cast<MM_COPY_ADDRESS*>(&ctl->Source),
		                          ctl->Size, MM_COPY_MEMORY_PHYSICAL, &ctl->Result);
	case Ctl::VIRT_QUERY:
		return NtQueryVirtualMemory(HANDLE(ctl->Pid), ctl->Source, MemoryBasicInformation,
		                            ctl->Target, sizeof(MEMORY_BASIC_INFORMATION), &ctl->Result);
	case Ctl::VIRT_READ:
#if USE_PHYSMEM
		return Phys::ReadProcessMemory(HANDLE(ctl->Pid), ctl->Source, ctl->Target, ctl->Size, &ctl->Result);
#else
		return ReadVirtualMemory(HANDLE(ctl->Pid), ctl->Source, ctl->Target, ctl->Size, &ctl->Result);
#endif

	case Ctl::VIRT_WRITE:
#if USE_PHYSMEM
		return Phys::WriteProcessMemory(HANDLE(ctl->Pid), ctl->Target, ctl->Source, ctl->Size, &ctl->Result);
#else
		return WriteVirtualMemory(HANDLE(ctl->Pid), ctl->Target, ctl->Source, ctl->Size, &ctl->Result);
#endif
	default:
		log("Invalid ctlCode: 0x%x", ctl->CtlCode);
		return STATUS_INVALID_PARAMETER;
	}
}


NTSTATUS ReadVirtualMemory(HANDLE pid, PVOID va, PVOID buffer, SIZE_T size, PSIZE_T bytesRead)
{
	PEPROCESS proc;

	if (!NT_SUCCESS(C_FN(PsLookupProcessByProcessId)(pid, &proc)))
	{
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

	if (!NT_SUCCESS(status))
		log("Va read at [0x%p] failed with status 0x%x", va, status);

	return status;
}

NTSTATUS WriteVirtualMemory(HANDLE pid, PVOID va, PVOID buffer, SIZE_T size, PSIZE_T bytesRead)
{
	PEPROCESS proc;
	if (!NT_SUCCESS(C_FN(PsLookupProcessByProcessId)(pid, &proc)))
	{
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

	if (!NT_SUCCESS(status))
		log("Va write at [0x%p] failed with status 0x%x", va, status);

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
