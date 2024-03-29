#include "clear.hpp"
#include "search.hpp"
#include "skcrypt.hpp"
#include "util.hpp"

using namespace Search;

NTSTATUS Clear::CleanupMiscTraces(DriverState* driverState)
{
	NTSTATUS status;
	// Probably detected
	// status = Clear::SpoofDiskSerials(Search::Kernel.Base, &driverState->OriginalDiskDispatchFn);
	// if (!NT_SUCCESS(status))
	// {
	// 	log(skCrypt("[rwdrv] Spoofing disk serials failed");
	// 	return status;
	// }

	if (driverState->ImageSize >= 0x1000 && !NT_SUCCESS(
		status = ClearSystemBigPoolInfo(driverState->BaseAddress)
	))
	{
		log("Clearing BigPoolInfo failed");
		return status;
	}
	
	if (!NT_SUCCESS(
		status = ClearPfnEntry(driverState->BaseAddress, driverState->ImageSize)
	))
	{
		log("Clearing Pfn table entry failed");
		return status;
	}
	if (!NT_SUCCESS(
		status = ClearCiEaCache()
	))
	{
		log("Clearing CiEaCacheLookasideList failed");
		return status;
	}
	log("Traces successfully cleared");
	driverState->TracesCleaned = true;
	return STATUS_SUCCESS;
}


// NTSTATUS Clear::SpoofDiskSerials(PVOID kernelBase, PDRIVER_DISPATCH* originalDispatchAddress)
// {
// 	// Pasted from
// 	// https://www.unknowncheats.me/forum/anti-cheat-bypass/425937-spoofing-disk-smart-serials-hooks-technically.html
// 	
// 	UNREFERENCED_PARAMETER(kernelBase);
// 	log("Spoofing disk serials");
//
// 	UNICODE_STRING driverDisk;
// 	C_FN(RtlInitUnicodeString)(&driverDisk, skCrypt(L"\\Driver\\Disk"));
//
// 	UNICODE_STRING objName;
// 	C_FN(RtlInitUnicodeString)(&objName, skCrypt(L"IoDriverObjectType"));
//
// 	auto* const driverObjectType =
// 		static_cast<POBJECT_TYPE*>(C_FN(MmGetSystemRoutineAddress)(&objName));
//
// 	if (driverObjectType == nullptr)
// 	{
// 		log("Failed to get IoDriverObjectType");
// 		return STATUS_UNSUCCESSFUL;
// 	}
//
// 	PDRIVER_OBJECT driverObject{};
//
// 	const auto status = C_FN(ObReferenceObjectByName)(
// 		&driverDisk,
// 		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
// 		nullptr,
// 		NULL,
// 		*driverObjectType,
// 		KernelMode,
// 		nullptr,
// 		reinterpret_cast<PVOID*>(&driverObject)
// 	);
// 	if (!NT_SUCCESS(status))
// 		return STATUS_UNSUCCESSFUL;
//
// 	*originalDispatchAddress = PDRIVER_DISPATCH(
// 		InterlockedExchangePointer(
// 			reinterpret_cast<void**>(&driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]),
// 			driverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION]
// 		));
//
// 	C_FN(ObfDereferenceObject)(driverObject);
//
// 	return STATUS_SUCCESS;
// }


NTSTATUS Clear::ClearPfnEntry(PVOID pageAddress, ULONG pageSize)
{
	log("Removing Pfn database entry");
	log("Allocating MDL for [0x%p]; size %u", pageAddress, pageSize);
	auto* const mdl = C_FN(IoAllocateMdl)(PVOID(pageAddress), pageSize, false, false, nullptr);

	if (mdl == nullptr)
	{
		log("MDL allocation failed");
		return STATUS_UNSUCCESSFUL;
	}

	auto* const mdlPages = MmGetMdlPfnArray(mdl);
	if (!mdlPages)
	{
		C_FN(IoFreeMdl)(mdl);
		log("MmGetMdlPfnArray failed");
		return STATUS_UNSUCCESSFUL;
	}

	const ULONG mdlPageCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(mdl), MmGetMdlByteCount(mdl));

	log("MDL page count: %u", mdlPageCount);

	ULONG nullPfn = 0x0;
	MM_COPY_ADDRESS sourceAddress{};
	sourceAddress.VirtualAddress = &nullPfn;

	for (ULONG i = 0; i < mdlPageCount; i++)
	{
		size_t bytes = 0;
		C_FN(MmCopyMemory)(&mdlPages[i], sourceAddress, sizeof(ULONG), MM_COPY_MEMORY_VIRTUAL, &bytes);
	}

	C_FN(IoFreeMdl)(mdl);

	log("Successfully cleared Pfns");
	return STATUS_SUCCESS;
}

NTSTATUS Clear::ClearCiEaCache()
{
	RTL_OSVERSIONINFOW ver{};
	C_FN(RtlGetVersion)(&ver);

	const auto instr = FindPatternInSection(
		g::CIdll, skCrypt("PAGE"),
		PBYTE(PCHAR(
			skCrypt("\x8B\xD8\xFF\x05\x00\x00\x00\x00")
		)), skCrypt("xxxx????")
	);

	if (instr == NULL)
	{
		log("Could not find CiEaCache");
		return STATUS_NOT_FOUND;
	}

	const auto ptr = RVA(instr + 8, 3);

	log("Found CIEaCacheLookasideList at [0x%p], flushing", ptr);

	C_FN(ExFlushLookasideListEx)(PLOOKASIDE_LIST_EX(ptr));

	return STATUS_SUCCESS;
}


BOOLEAN FindBigPoolTable(PPOOL_TRACKER_BIG_PAGES** poolBigPageTable, SIZE_T* poolBigPageTableSize) // FIXME
{
	const auto bptSize = FindPatternInSection(
		g::Kernel, skCrypt(".text"),
		PBYTE(PCHAR(
			skCrypt("\x4C\x8B\x15\x00\x00\x00\x00\x48\x85")
		)), skCrypt("xxx????xx")
	);

	const auto bpt = FindPatternInSection(
		g::Kernel, skCrypt(".text"),
		PBYTE(PCHAR(
			skCrypt("\x48\x8B\x15\x00\x00\x00\x00\x4C\x8D\x0D\x00\x00\x00\x00\x4C")
		)), skCrypt("xxx????xxx????x")
	);

	if (!bptSize || !bpt)
	{
		return false;
	}

	*poolBigPageTable = static_cast<PPOOL_TRACKER_BIG_PAGES*>(RVA(bpt, 3));
	*poolBigPageTableSize = *PSIZE_T(RVA(bptSize, 3));
	return true;
}


bool FindBigPoolTableAlt(PPOOL_TRACKER_BIG_PAGES** pPoolBigPageTable, SIZE_T* pPoolBigPageTableSize)
{
	const auto exProtectPoolExCallInstructionsAddress = FindPatternInSection(
		g::Kernel, skCrypt(".text"),
		PBYTE(PCHAR(
			skCrypt("\xE8\x00\x00\x00\x00\x83\x67\x0C\x00")
		)), skCrypt("x????xxxx")
	);

	if (!exProtectPoolExCallInstructionsAddress)
		return false;

	auto exProtectPoolExAddress = RVA(exProtectPoolExCallInstructionsAddress, 1);

	if (!exProtectPoolExAddress)
		return false;

	const auto poolBigPageTableInstructionAddress = UINT64(exProtectPoolExAddress) + 0x95;
	*pPoolBigPageTable = static_cast<PPOOL_TRACKER_BIG_PAGES*>(
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
	PPOOL_TRACKER_BIG_PAGES* pPoolBigPageTable;

	log("Clearing SystemBigPoolInfo");

	if (!FindBigPoolTable(&pPoolBigPageTable, &bigPoolTableSize))
	{
		log("First method of finding BigPoolTable failed, trying alt method");
		if (!FindBigPoolTableAlt(&pPoolBigPageTable, &bigPoolTableSize))
		{
			log("Could not find BigPoolTable");
			return STATUS_UNSUCCESSFUL;
		}
	}

	PPOOL_TRACKER_BIG_PAGES poolBigPageTable{};
	RtlCopyMemory(&poolBigPageTable, PVOID(pPoolBigPageTable), 8);

	log("Found BigPoolPageTable at [0x%p] of size %llu; scanning", poolBigPageTable, bigPoolTableSize);

	auto cleared = false;

	for (size_t i = 0; i < bigPoolTableSize; i++)
	{
		auto va = poolBigPageTable[i].Va;
		if (va == ULONGLONG(pageAddr) || va == ULONGLONG(pageAddr) + 0x1)
		{
			char tag[5] = {0};
			RtlCopyMemory(tag, &poolBigPageTable[i].Key, 4);
			log("Found an entry in BigPoolTable: [0x%p] | Size: 0x%llX | Tag: '%s'",
			    PVOID(va),
			    poolBigPageTable[i].NumberOfBytes, tag);
			poolBigPageTable[i].Va = 0x1;
			poolBigPageTable[i].NumberOfBytes = 0x0;
			cleared = true;
			//return STATUS_SUCCESS;
		}
	}
	if (!cleared)
	{
		log("WARN: Entry in BigPoolTable not found!");
		//return STATUS_NOT_FOUND;
	}
	return STATUS_SUCCESS;
}
