#include "clean.hpp"

using namespace Search;

extern DriverState g_driverState;

NTSTATUS Clear::SpoofDiskSerials()
{
	// Pasted from
	// https://www.unknowncheats.me/forum/anti-cheat-bypass/425937-spoofing-disk-smart-serials-hooks-technically.html
	
	log(skCrypt("[rwdrv] Spoofing disk serials\n"));
	UNICODE_STRING driverDisk;
	RtlInitUnicodeString(&driverDisk, L"\\Driver\\Disk");

	PDRIVER_OBJECT driverObject;
	const auto status = ObReferenceObjectByName(
		&driverDisk,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		nullptr,
		NULL,
		*IoDriverObjectType,
		KernelMode,
		nullptr,
		reinterpret_cast<PVOID*>(&driverObject)
	);
	if (!NT_SUCCESS(status))
		return STATUS_UNSUCCESSFUL;

	g_driverState.OriginalDiskDispatchFn = driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];

	driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION];

	ObDereferenceObject(driverObject);
	return STATUS_SUCCESS;
}

bool FindBigPoolTableAlt(PPOOL_TRACKER_BIG_PAGES* pPoolBigPageTable, SIZE_T* pPoolBigPageTableSize)
{
	const auto ExProtectPoolExCallInstructionsAddress = PVOID(FindPattern(
		reinterpret_cast<UINT64>(KernelBase),
		KernelSize,
		reinterpret_cast<BYTE*>(static_cast<char*>((
				skCrypt("\xE8\x00\x00\x00\x00\x83\x67\x0C\x00"))
		)),
		skCrypt("x????xxxx")
	));

	if (!ExProtectPoolExCallInstructionsAddress)
		return false;

	PVOID ExProtectPoolExAddress = ResolveRelativeAddress(ExProtectPoolExCallInstructionsAddress, 1, 5);

	if (!ExProtectPoolExAddress)
		return false;

	const auto PoolBigPageTableInstructionAddress = PVOID(ULONG64(ExProtectPoolExAddress) + 0x95);
	*pPoolBigPageTable = reinterpret_cast<PPOOL_TRACKER_BIG_PAGES>(
		ResolveRelativeAddress(PoolBigPageTableInstructionAddress, 3, 7));

	const auto PoolBigPageTableSizeInstructionAddress = PVOID(ULONG64(ExProtectPoolExAddress) + 0x8E);
	*pPoolBigPageTableSize = *static_cast<SIZE_T*>(
		ResolveRelativeAddress(PoolBigPageTableSizeInstructionAddress, 3, 7));

	return true;
}

BOOLEAN FindBigPoolTable(PPOOL_TRACKER_BIG_PAGES* poolBigPageTable, SIZE_T* poolBigPageTableSize) // FIXME
{
	const auto bptSize =
		reinterpret_cast<PVOID>(FindPattern(
				reinterpret_cast<UINT64>(KernelBase),
				KernelSize,
				reinterpret_cast<BYTE*>( // Pattern
					static_cast<char*>(
						skCrypt("\x4C\x8B\x15\x00\x00\x00\x00\x48\x85")
					)),
				skCrypt("xxx????xx"))
		);

	const auto bpt =
		reinterpret_cast<PVOID>(FindPattern(
			reinterpret_cast<UINT64>(KernelBase),
			KernelSize,
			reinterpret_cast<BYTE*>(
				static_cast<char*>(
					skCrypt("\x48\x8B\x15\x00\x00\x00\x00\x4C\x8D\x0D\x00\x00\x00\x00\x4C")
				)),
			skCrypt("xxx????xxx????x")
		));

	if (!bptSize || !bpt)
	{
		return false;
	}

	*poolBigPageTable = static_cast<PPOOL_TRACKER_BIG_PAGES>(ResolveRelativeAddress(bpt, 3, 7));
	*poolBigPageTableSize = *static_cast<PSIZE_T>(ResolveRelativeAddress(bptSize, 3, 7));
	return true;
}


NTSTATUS Clear::ClearSystemBigPoolInfo(PVOID64 pageAddr)
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

	for (size_t i = 0; i < bigPoolTableSize; i++)
	{
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

	log(skCrypt("Entry in BigPoolTable not found!\n"));
	return STATUS_SUCCESS;
}

NTSTATUS Clear::ClearPfnDatabase()
{
	// TODO
	return STATUS_SUCCESS;
}
