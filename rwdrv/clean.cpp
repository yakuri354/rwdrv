#include "clean.hpp"

using namespace Search;


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

	log(skCrypt("[rwdrv] Retrieving Windows version\n"));

	RTL_OSVERSIONINFOW winver;

	if (!RtlGetVersion(&winver))
	{
		log(skCrypt("[rwdrv] Retrieving Windows version failed\n"));
		return STATUS_UNSUCCESSFUL;
	}

	log(skCrypt("[rwdrv] Windows version %ul\n"), winver.dwMajorVersion);


	if (!FindBigPoolTable(&pPoolBigPageTable, &bigPoolTableSize))
	{
		log(skCrypt("[rwdrv] First method of finding BigPoolTable failed, trying alt method\n"));
		if (!FindBigPoolTableAlt(&pPoolBigPageTable, &bigPoolTableSize))
		{
			log(skCrypt("[rwdrv] Could not find BigPoolTable\n"));
			return STATUS_UNSUCCESSFUL;
		}
	}

	log(skCrypt("[rwdrv] Successfully found BigPoolTable at [%X], size %X\n"), pPoolBigPageTable, bigPoolTableSize);

	PPOOL_TRACKER_BIG_PAGES PoolBigPageTable = nullptr;
	RtlCopyMemory(&PoolBigPageTable, static_cast<PVOID>(pPoolBigPageTable), 8);

	for (size_t i = 0; i < bigPoolTableSize; i++)
	{
		if (PoolBigPageTable[i].Va == ULONGLONG(pageAddr) || PoolBigPageTable[i].Va == ULONGLONG(pageAddr) + 0x1)
		{
			log(skCrypt("Found an entry in BigPoolTable [%X], Tag: %X, Size: %u\n"),
			    PoolBigPageTable[i].Va,
			    PoolBigPageTable[i].Key,
			    PoolBigPageTable[i].NumberOfBytes);
			PoolBigPageTable[i].Va = 0x1;
			PoolBigPageTable[i].NumberOfBytes = 0x0;
			return STATUS_SUCCESS;
		}
	}

	log(skCrypt("Entry [%X] in BigPoolTable not found!\n"), pageAddr);
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS Clear::ClearPfnDatabase()
{
	// TODO
	return STATUS_SUCCESS;
}