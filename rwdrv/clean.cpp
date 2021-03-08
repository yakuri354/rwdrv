#include "clean.hpp"
#include "search.hpp"
#include "skcrypt.hpp"
#include "util.hpp"

using namespace Search;

// TODO Great refactor of pasted code

NTSTATUS Clear::SpoofDiskSerials(PVOID kernelBase, PDRIVER_DISPATCH* originalDispatchAddress)
{
	// Pasted from
	// https://www.unknowncheats.me/forum/anti-cheat-bypass/425937-spoofing-disk-smart-serials-hooks-technically.html
	UNREFERENCED_PARAMETER(kernelBase);
	log(skCrypt("[rwdrv] Spoofing disk serials\n"));

	UNICODE_STRING driverDisk;

	C_FN(RtlUnicodeStringInit)(&driverDisk, skCrypt(L"\\Driver\\Disk"));

	UNICODE_STRING objName;
	C_FN(RtlUnicodeStringInit)(&objName, skCrypt(L"IoDriverObjectType"));
	const auto driverObjectType = // Yep, it does actually work
		static_cast<POBJECT_TYPE*>(C_FN(MmGetSystemRoutineAddress)(&objName));

	if (driverObjectType == nullptr)
	{
		log(skCrypt("[rwdrv] Failed to get IoDriverObjectType\n"));
		return STATUS_UNSUCCESSFUL;
	}

	PDRIVER_OBJECT driverObject;

	const auto status = C_FN(ObReferenceObjectByName)(
		&driverDisk,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		nullptr,
		NULL,
		*driverObjectType,
		KernelMode,
		nullptr,
		reinterpret_cast<PVOID*>(&driverObject)
	);
	if (!NT_SUCCESS(status))
		return STATUS_UNSUCCESSFUL;

	// *originalDispatchAddress = driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	//
	// driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION];

	*originalDispatchAddress = PDRIVER_DISPATCH(
		InterlockedExchangePointer(
			reinterpret_cast<void**>(&driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]),
			driverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION]
		));

	C_FN(ObfDereferenceObject)(driverObject);

	return STATUS_SUCCESS;
}

NTSTATUS Clear::ClearPfnEntry(PVOID pageAddress, ULONG pageSize)
{
	// TODO Fix this

	log(skCrypt("[rwdrv] Removing Pfn database entry\n"));
	log(skCrypt("[rwdrv] Allocating MDL for address [%p] and size %u\n"), pageAddress, pageSize);
	const auto mdl = C_FN(IoAllocateMdl)(PVOID(pageAddress), pageSize, false, false, nullptr);

	if (mdl == nullptr)
	{
		log(skCrypt("[rwdrv] MDL allocation failed\n"));
		return STATUS_UNSUCCESSFUL;
	}

	const auto mdlPages = MmGetMdlPfnArray(mdl);
	if (!mdlPages)
	{
		log(skCrypt("[rwdrv] MmGetMdlPfnArray failed\n"));
		return STATUS_UNSUCCESSFUL;
	}

	const ULONG mdlPageCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(mdl), MmGetMdlByteCount(mdl));

	log(skCrypt("[rwdrv] MDL page count: %u\n"), mdlPageCount);

	ULONG nullPfn = 0x0;
	MM_COPY_ADDRESS sourceAddress{};
	sourceAddress.VirtualAddress = &nullPfn;

	for (ULONG i = 0; i < mdlPageCount; i++)
	{
		size_t bytes = 0;
		C_FN(MmCopyMemory)(&mdlPages[i], sourceAddress, sizeof(ULONG), MM_COPY_MEMORY_VIRTUAL, &bytes);
	}

	log(skCrypt("[rwdrv] Successfully cleared Pfn database\n"));
	return STATUS_SUCCESS;
}


BOOLEAN FindBigPoolTable(PPOOL_TRACKER_BIG_PAGES* poolBigPageTable, SIZE_T* poolBigPageTableSize) // FIXME
{
	const auto bptSize = FindPattern(
		reinterpret_cast<UINT64>(KernelBase),
		KernelSize,
		reinterpret_cast<BYTE*>( // Pattern
			static_cast<char*>(
				skCrypt("\x4C\x8B\x15\x00\x00\x00\x00\x48\x85")
			)),
		skCrypt("xxx????xx")
	);

	const auto bpt = FindPattern(
		reinterpret_cast<UINT64>(KernelBase),
		KernelSize,
		reinterpret_cast<BYTE*>(
			static_cast<char*>(
				skCrypt("\x48\x8B\x15\x00\x00\x00\x00\x4C\x8D\x0D\x00\x00\x00\x00\x4C")
			)),
		skCrypt("xxx????xxx????x")
	);

	if (!bptSize || !bpt)
	{
		return false;
	}

	*poolBigPageTable = static_cast<PPOOL_TRACKER_BIG_PAGES>(RVA(bpt, 3));
	*poolBigPageTableSize = *static_cast<PSIZE_T>(RVA(bptSize, 3));
	return true;
}

bool FindBigPoolTableAlt(PPOOL_TRACKER_BIG_PAGES* pPoolBigPageTable, SIZE_T* pPoolBigPageTableSize)
{
	const auto exProtectPoolExCallInstructionsAddress = FindPattern(
		reinterpret_cast<UINT64>(KernelBase),
		KernelSize,
		reinterpret_cast<BYTE*>(static_cast<char*>((
				skCrypt("\xE8\x00\x00\x00\x00\x83\x67\x0C\x00"))
		)),
		skCrypt("x????xxxx")
	);

	if (!exProtectPoolExCallInstructionsAddress)
		return false;

	auto exProtectPoolExAddress = RVA(exProtectPoolExCallInstructionsAddress, 1);

	if (!exProtectPoolExAddress)
		return false;

	const auto poolBigPageTableInstructionAddress = UINT64(exProtectPoolExAddress) + 0x95;
	*pPoolBigPageTable = PPOOL_TRACKER_BIG_PAGES(
		RVA(poolBigPageTableInstructionAddress, 3)
	);

	const auto poolBigPageTableSizeInstructionAddress = UINT64(exProtectPoolExAddress) + 0x8E;
	*pPoolBigPageTableSize = *static_cast<SIZE_T*>(
		RVA(poolBigPageTableSizeInstructionAddress, 3));

	return true;
}

NTSTATUS Clear::ClearSystemBigPoolInfo(PVOID pageAddr)
{
	SIZE_T bigPoolTableSize;
	PPOOL_TRACKER_BIG_PAGES pPoolBigPageTable;

	log(skCrypt("[rwdrv] Clearing SystemBigPoolInfo\n"));


	if (!FindBigPoolTable(&pPoolBigPageTable, &bigPoolTableSize))
	{
		log(skCrypt("[rwdrv] First method of finding BigPoolTable failed, trying alt method\n"));
		if (!FindBigPoolTableAlt(&pPoolBigPageTable, &bigPoolTableSize))
		{
			log(skCrypt("[rwdrv] Could not find BigPoolTable\n"));
			return STATUS_UNSUCCESSFUL;
		}
	}

	log(skCrypt("[rwdrv] Successfully found BigPoolTable at [0x%p], size %Iu\n"), pPoolBigPageTable, bigPoolTableSize);

	PPOOL_TRACKER_BIG_PAGES poolBigPageTable = nullptr;
	RtlCopyMemory(&poolBigPageTable, static_cast<PVOID>(pPoolBigPageTable), 8);

	log(skCrypt("[rwdrv] Searching for address [%p]\n"), pageAddr);

	for (size_t i = 0; i < bigPoolTableSize; i++)
	{
		// log("%p %lld\n", poolBigPageTable[i].Va, poolBigPageTable[i].NumberOfBytes);
		if (poolBigPageTable[i].Va == ULONGLONG(pageAddr) || poolBigPageTable[i].Va == ULONGLONG(pageAddr) + 0x1)
		{
			log(skCrypt("[rwdrv] Found an entry in BigPoolTable [0x%p], Tag: [0x%lX], Size: [%lld]\n"),
			    PVOID(poolBigPageTable[i].Va),
			    poolBigPageTable[i].Key,
			    poolBigPageTable[i].NumberOfBytes);
			poolBigPageTable[i].Va = 0x1;
			poolBigPageTable[i].NumberOfBytes = 0x0;
			return STATUS_SUCCESS;
		}
	}

	log(skCrypt("[rwdrv] Entry in BigPoolTable not found!\n"));
	// return STATUS_NOT_FOUND;
	return STATUS_SUCCESS;
}

