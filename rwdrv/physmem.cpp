#include "physmem.hpp"

DWORD GetUserDirectoryTableBaseOffset();
ULONG_PTR GetProcessCr3(PEPROCESS pProcess);
UINT64 TranslateLinearAddress(UINT64 directoryTableBase, UINT64 virtualAddress);

DWORD GetUserDirectoryTableBaseOffset()
{
	RTL_OSVERSIONINFOW ver = { 0 };
	C_FN(RtlGetVersion)(&ver);

	switch (ver.dwBuildNumber)
	{
	case WINDOWS_1803:
	case WINDOWS_1809:
		return 0x0278;

	case WINDOWS_1903:
	case WINDOWS_1909:
		return 0x0280;

	case WINDOWS_2004:
	case WINDOWS_20H2:
	case WINDOWS_21H1:
	default:
		return 0x0388;
	}
}

//check normal dirbase if 0 then get from UserDirectoryTableBas
ULONG_PTR GetProcessCr3(PEPROCESS pProcess)
{
	const auto process = UINT64(pProcess);
	const auto processDirbase = *PULONG_PTR(process + 0x28); //dirbase x64, 32bit is 0x18
	if (processDirbase == 0)
	{
		const auto userDirOffset = GetUserDirectoryTableBaseOffset();
		const auto processUserDirbase = *PULONG_PTR(process + userDirOffset);
		return processUserDirbase;
	}
	return processDirbase;
}

ULONG_PTR GetKernelDirBase()
{
	const auto process = UINT64(C_FN(IoGetCurrentProcess)());
	const auto cr3 = *PULONG_PTR(process + 0x28); //dirbase x64, 32bit is 0x18
	return cr3;
}

NTSTATUS Phys::ReadVirtual(UINT64 dirbase, UINT64 address, BYTE* buffer, SIZE_T size, SIZE_T* read)
{
	const auto paddress = TranslateLinearAddress(dirbase, address);
	return ReadPhysicalAddress(PVOID(paddress), buffer, size, read);
}

NTSTATUS Phys::WriteVirtual(UINT64 dirbase, UINT64 address, BYTE* buffer, SIZE_T size, SIZE_T* written)
{
	const auto paddress = TranslateLinearAddress(dirbase, address);
	return WritePhysicalAddress(PVOID(paddress), buffer, size, written);
}

NTSTATUS Phys::ReadPhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
{
	MM_COPY_ADDRESS addrToRead;
	addrToRead.PhysicalAddress.QuadPart = UINT64(TargetAddress);
	return C_FN(MmCopyMemory)(lpBuffer, addrToRead, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
}

//MmMapIoSpaceEx limit is page 4096 byte
NTSTATUS Phys::WritePhysicalAddress(PVOID targetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten)
{
	if (!targetAddress)
		return STATUS_PARTIAL_COPY; // TODO ugly

	PHYSICAL_ADDRESS AddrToWrite = { 0 };
	AddrToWrite.QuadPart = UINT64(targetAddress);

	auto* const pmappedMem = C_FN(MmMapIoSpaceEx)(AddrToWrite, Size, PAGE_READWRITE);

	if (!pmappedMem)
		return STATUS_PARTIAL_COPY;

	memcpy(pmappedMem, lpBuffer, Size);

	*BytesWritten = Size;
	C_FN(MmUnmapIoSpace)(pmappedMem, Size);
	return STATUS_SUCCESS;
}

UINT64 TranslateLinearAddress(UINT64 directoryTableBase, UINT64 virtualAddress)
{
	const auto pml4 = UINT16((virtualAddress >> 39) & 0x1FF); ///< PML4 Entry Index
	const auto directoryPtr = UINT16((virtualAddress >> 30) & 0x1FF); ///< Page-Directory-Pointer Table Index
	const auto directory = UINT16((virtualAddress >> 21) & 0x1FF); ///< Page Directory Table Index
	const auto table = UINT16((virtualAddress >> 12) & 0x1FF); ///< Page Table Index

	// Read the PML4 Entry. DirectoryTableBase has the base address of the table.
	// It can be read from the CR3 register or from the kernel process object.

	UINT64 pml4E = 0; // ReadPhysicalAddress<ulong>(directoryTableBase + (ulong)PML4 * sizeof(ulong));

	SIZE_T readsize = 0;
	Phys::ReadPhysicalAddress(PVOID(directoryTableBase + UINT64(pml4) * sizeof(UINT64)), &pml4E, sizeof(pml4E),
	                          &readsize);

	if (pml4E == 0)
		return 0;

	// The PML4E that we read is the base address of the next table on the chain,
	// the Page-Directory-Pointer Table.
	UINT64 pdpte = 0; // ReadPhysicalAddress<ulong>((PML4E & 0xFFFF1FFFFFF000) + (ulong)DirectoryPtr * sizeof(ulong));
	Phys::ReadPhysicalAddress(PVOID((pml4E & 0xFFFF1FFFFFF000) + UINT64(directoryPtr) * sizeof(UINT64)), &pdpte,
	                          sizeof(pdpte), &readsize);

	if (pdpte == 0)
		return 0;

	//Check the PS bit
	if ((pdpte & (1 << 7)) != 0)
	{
		// If the PDPTE¨s PS flag is 1, the PDPTE maps a 1-GByte page. The
		// final physical address is computed as follows:
		// ！ Bits 51:30 are from the PDPTE.
		// ！ Bits 29:0 are from the original va address.
		return (pdpte & 0xFFFFFC0000000) + (virtualAddress & 0x3FFFFFFF);
	}

	// PS bit was 0. That means that the PDPTE references the next table
	// on the chain, the Page Directory Table. Read it.
	UINT64 pde = 0; // ReadPhysicalAddress<ulong>((PDPTE & 0xFFFFFFFFFF000) + (ulong)Directory * sizeof(ulong));
	Phys::ReadPhysicalAddress(PVOID((pdpte & 0xFFFFFFFFFF000) + UINT64(directory) * sizeof(UINT64)), &pde, sizeof(pde),
	                          &readsize);

	if (pde == 0)
		return 0;

	if ((pde & (1 << 7)) != 0)
	{
		// If the PDE¨s PS flag is 1, the PDE maps a 2-MByte page. The
		// final physical address is computed as follows:
		// ！ Bits 51:21 are from the PDE.
		// ！ Bits 20:0 are from the original va address.
		return (pde & 0xFFFFFFFE00000) + (virtualAddress & 0x1FFFFF);
	}

	// PS bit was 0. That means that the PDE references a Page Table.
	UINT64 pte = 0; // ReadPhysicalAddress<ulong>((PDE & 0xFFFFFFFFFF000) + (ulong)Table * sizeof(ulong));
	Phys::ReadPhysicalAddress(PVOID((pde & 0xFFFFFFFFFF000) + (UINT64)table * sizeof(UINT64)), (BYTE*)&pte, sizeof(pte),
	                          &readsize);


	if (pte == 0)
		return 0;

	// The PTE maps a 4-KByte page. The
	// final physical address is computed as follows:
	// ！ Bits 51:12 are from the PTE.
	// ！ Bits 11:0 are from the original va address.
	return (pte & 0xFFFFFFFFFF000) + (virtualAddress & 0xFFF);
}



NTSTATUS Phys::ReadProcessMemory(HANDLE pid, PVOID va, PVOID buffer, SIZE_T size, SIZE_T* read)
{
	PEPROCESS pProcess{};

	const auto status = C_FN(PsLookupProcessByProcessId)(HANDLE(pid), &pProcess);
	if (status != STATUS_SUCCESS) return STATUS_NOT_FOUND;

	const auto processDirbase = GetProcessCr3(pProcess);
	C_FN(ObfDereferenceObject)(pProcess);

	SIZE_T curOffset = 0;
	auto totalSize = size;
	while (totalSize)
	{
		const auto curPhysAddr = TranslateLinearAddress(processDirbase, ULONG64(va) + curOffset);
		if (!curPhysAddr) return STATUS_PARTIAL_COPY;

		auto readSize = min(PAGE_SIZE - (curPhysAddr & 0xFFF), totalSize);
		const auto ntRet = ReadPhysicalAddress(PVOID(curPhysAddr), PVOID(ULONG64(buffer) + curOffset), readSize,
		                                             &readSize);
		totalSize -= readSize;
		curOffset += readSize;
		if (ntRet != STATUS_SUCCESS) break;
	}

	*read = curOffset;
	return status;
}

NTSTATUS Phys::WriteProcessMemory(HANDLE pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* written)
{
	PEPROCESS pProcess{};

	const auto status = C_FN(PsLookupProcessByProcessId)(HANDLE(pid), &pProcess);
	if (status != STATUS_SUCCESS) return STATUS_NOT_FOUND;

	const auto processDirbase = GetProcessCr3(pProcess);
	C_FN(ObfDereferenceObject)(pProcess);

	SIZE_T curOffset = 0;
	auto totalSize = size;
	while (totalSize)
	{
		const auto curPhysAddr = TranslateLinearAddress(processDirbase, ULONG64(Address) + curOffset);
		if (!curPhysAddr) return STATUS_PARTIAL_COPY;

		auto writtenSize = min(PAGE_SIZE - (curPhysAddr & 0xFFF), totalSize);
		const auto ntRet = WritePhysicalAddress(PVOID(curPhysAddr), PVOID(ULONG64(AllocatedBuffer) + curOffset),
		                                              writtenSize, &writtenSize);
		totalSize -= writtenSize;
		curOffset += writtenSize;
		if (ntRet != STATUS_SUCCESS) break;
	}

	*written = curOffset;
	return status;
}
