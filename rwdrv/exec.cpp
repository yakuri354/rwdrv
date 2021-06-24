#include "exec.hpp"

NTSTATUS UnloadDriver(DriverState* state);
NTSTATUS CopyVirtualMemory(bool writeToPid, HANDLE pid, PVOID source, PVOID target, SIZE_T size, PSIZE_T bytesRead);

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
	case Ctl::VIRT_READ:
#if USE_PHYSMEM
		return Phys::ReadProcessMemory(HANDLE(ctl->Pid), ctl->Source, ctl->Target, ctl->Size, &ctl->Result);
#else
		return CopyVirtualMemory(false, HANDLE(ctl->Pid), ctl->Source, ctl->Target, ctl->Size, &ctl->Result);
#endif

	case Ctl::VIRT_WRITE:
#if USE_PHYSMEM
		return Phys::WriteProcessMemory(HANDLE(ctl->Pid), ctl->Target, ctl->Source, ctl->Size, &ctl->Result);
#else
		return CopyVirtualMemory(true, HANDLE(ctl->Pid), ctl->Source, ctl->Target, ctl->Size, &ctl->Result);
#endif
	default:
		log("Invalid ctlCode: 0x%x", ctl->CtlCode);
		return STATUS_INVALID_PARAMETER;
	}
}


F_INLINE NTSTATUS CopyVirtualMemory(bool writeToPid, HANDLE pid, PVOID source, PVOID target, SIZE_T size, PSIZE_T bytesRead)
{
	PEPROCESS proc{};
	NTSTATUS status = STATUS_FWP_NULL_POINTER;
	SIZE_T bytesReadKm{};
	if (!NT_SUCCESS(C_FN(PsLookupProcessByProcessId)(pid, &proc)))
	{
		log("Process %llu not found", UINT64(pid));
		return STATUS_NOT_FOUND;
	}

	if (target == nullptr || source == nullptr || !NT_SUCCESS(
		status = C_FN(MmCopyVirtualMemory)(
			writeToPid ? C_FN(IoGetCurrentProcess)() : proc,
			source,
			writeToPid ? proc : C_FN(IoGetCurrentProcess)(),
			target,
			size,
			UserMode,
			&bytesReadKm
		)))
		log("Memcpy from [0x%p] to [0x%p] failed with status 0x%x", source, target, status);

	C_FN(ObfDereferenceObject)(proc);

	*bytesRead = bytesReadKm;
	
	return status;
}

F_INLINE NTSTATUS UnloadDriver(DriverState* state)
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
