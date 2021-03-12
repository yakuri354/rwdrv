#include "physmem.hpp"

ULONG_PTR Phys::GetKernelDirBase()
{
	const auto process = PUCHAR(C_FN(IoGetCurrentProcess)());
	const auto cr3 = *PULONG_PTR(process + 0x28); //dirbase x64, 32bit is 0x18
	return cr3;
}

NTSTATUS Phys::ReadVirtual(UINT64 dirbase, UINT64 address, char* buffer, SIZE_T size, SIZE_T* read)
{
	const auto paddress = Phys::TranslateLinearAddress(dirbase, address);
	return ReadPhysicalAddress(PVOID(paddress), buffer, size, read);
}

NTSTATUS Phys::WriteVirtual(UINT64 dirbase, UINT64 address, char* buffer, SIZE_T size, SIZE_T* written)
{
	const auto paddress = Phys::TranslateLinearAddress(dirbase, address);
	return Phys::WritePhysicalAddress(PVOID(paddress), buffer, size, written);
}

NTSTATUS Phys::ReadPhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
{
	MM_COPY_ADDRESS AddrToRead{};
	AddrToRead.PhysicalAddress.QuadPart = UINT64(TargetAddress);
	return MmCopyMemory(lpBuffer, AddrToRead, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
}

NTSTATUS Phys::WritePhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten)
{
	MM_COPY_ADDRESS AddrToWrite{};
	AddrToWrite.PhysicalAddress.QuadPart = UINT64(lpBuffer);
	return MmCopyMemory(TargetAddress, AddrToWrite, Size, MM_COPY_MEMORY_PHYSICAL, BytesWritten);
}

UINT64 Phys::TranslateLinearAddress(UINT64 directoryTableBase, UINT64 virtualAddress)
{
	const auto PML4 = UINT16((virtualAddress >> 39) & 0x1FF);         //<! PML4 Entry Index
	const auto DirectoryPtr = UINT16((virtualAddress >> 30) & 0x1FF); //<! Page-Directory-Pointer Table Index
	const auto Directory = UINT16((virtualAddress >> 21) & 0x1FF);    //<! Page Directory Table Index
	const auto Table = UINT16((virtualAddress >> 12) & 0x1FF);        //<! Page Table Index

																	// Read the PML4 Entry. DirectoryTableBase has the base address of the table.
																	// It can be read from the CR3 register or from the kernel process object.
	UINT64 PML4E = 0;// ReadPhysicalAddress<ulong>(directoryTableBase + (ulong)PML4 * sizeof(ulong));

	SIZE_T readsize = 0;
	ReadPhysicalAddress(PVOID(directoryTableBase + UINT64(PML4) * sizeof(UINT64)), PCHAR(&PML4E), sizeof(PML4E), &readsize);

	if (PML4E == 0)
		return 0;

	// The PML4E that we read is the base address of the next table on the chain,
	// the Page-Directory-Pointer Table.
	UINT64 PDPTE = 0;// ReadPhysicalAddress<ulong>((PML4E & 0xFFFF1FFFFFF000) + (ulong)DirectoryPtr * sizeof(ulong));
	ReadPhysicalAddress(PVOID((PML4E & 0xFFFF1FFFFFF000) + UINT64(DirectoryPtr) * sizeof(UINT64)), PCHAR(&PDPTE), sizeof(PDPTE), &readsize);

	if (PDPTE == 0)
		return 0;

	//Check the PS bit
	if ((PDPTE & (1 << 7)) != 0)
	{
		// If the PDPTE¨s PS flag is 1, the PDPTE maps a 1-GByte page. The
		// final physical address is computed as follows:
		// ！ Bits 51:30 are from the PDPTE.
		// ！ Bits 29:0 are from the original va address.
		return (PDPTE & 0xFFFFFC0000000) + (virtualAddress & 0x3FFFFFFF);
	}

	// PS bit was 0. That means that the PDPTE references the next table
	// on the chain, the Page Directory Table. Read it.
	UINT64 PDE = 0;// ReadPhysicalAddress<ulong>((PDPTE & 0xFFFFFFFFFF000) + (ulong)Directory * sizeof(ulong));
	ReadPhysicalAddress(PVOID((PDPTE & 0xFFFFFFFFFF000) + UINT64(Directory) * sizeof(UINT64)), PCHAR(&PDE), sizeof(PDE), &readsize);

	if (PDE == 0)
		return 0;

	if ((PDE & (1 << 7)) != 0)
	{
		// If the PDE¨s PS flag is 1, the PDE maps a 2-MByte page. The
		// final physical address is computed as follows:
		// ！ Bits 51:21 are from the PDE.
		// ！ Bits 20:0 are from the original va address.
		return (PDE & 0xFFFFFFFE00000) + (virtualAddress & 0x1FFFFF);
	}

	// PS bit was 0. That means that the PDE references a Page Table.
	UINT64 PTE = 0;// ReadPhysicalAddress<ulong>((PDE & 0xFFFFFFFFFF000) + (ulong)Table * sizeof(ulong));
	ReadPhysicalAddress(PVOID((PDE & 0xFFFFFFFFFF000) + UINT64(Table) * sizeof(UINT64)), PCHAR(&PTE), sizeof(PTE), &readsize);


	if (PTE == 0)
		return 0;

	// The PTE maps a 4-KByte page. The
	// final physical address is computed as follows:
	// ！ Bits 51:12 are from the PTE.
	// ！ Bits 11:0 are from the original va address.
	return (PTE & 0xFFFFFFFFFF000) + (virtualAddress & 0xFFF);
}

NTSTATUS Phys::ReadProcessMemory(int pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* read)
{
	PEPROCESS pProcess{};
	if (pid == 0) return STATUS_UNSUCCESSFUL;

	auto NtRet = C_FN(PsLookupProcessByProcessId)(HANDLE(pid), &pProcess);
	if (NtRet != STATUS_SUCCESS) return NtRet;


	const auto process = PUCHAR(pProcess);
	const auto process_dirbase = *PULONG_PTR(process + 0x28); //dirbase x64, 32bit is 0x18
	ObDereferenceObject(pProcess);

	if (size <= 4096)
		return ReadVirtual(process_dirbase, UINT64(Address), PCHAR(AllocatedBuffer), size, read);

	const auto pages = size / 4096;
	const auto remainder = size % 4096;
	size_t bytesread = 0;

	for (size_t i = 0; i < pages; i++)
	{
		NtRet = ReadVirtual(process_dirbase, UINT64(Address) + bytesread, PCHAR(AllocatedBuffer) + bytesread, 4096, read);
		bytesread += 4096;
	}

	if (remainder)
		return ReadVirtual(process_dirbase, UINT64(Address) + bytesread, PCHAR(AllocatedBuffer) + bytesread, remainder, read);

	return NtRet;
}