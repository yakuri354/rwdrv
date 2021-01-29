#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include "clean.hpp"
#include "skcrypt.h"

struct SharedMem
{
	PVOID SharedSection;
	HANDLE SectionHandle;
	SECURITY_DESCRIPTOR SecDescriptor;
};

struct DriverState
{
	SharedMem Mem;
	PVOID BaseAddress;
};

DriverState g_DriverState;

inline NTSTATUS BoolToNt(const bool b)
{
	return b ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS CleanupLoadingTraces(DriverState* driverState)
{
	log(skCrypt("[rwdrv] Cleaning traces\n"));

	UNICODE_STRING driverName;

	RtlInitUnicodeString(&driverName, skCrypt(L"iqvw64e.dll"));

	const auto result =
		clear::ClearMmUnloadedDrivers(&driverName, true) == STATUS_SUCCESS
		&& clear::ClearPiDDBCacheTable(driverName, NULL) == STATUS_SUCCESS
		&& clear::ClearSystemBigPoolInfo(driverState->BaseAddress) == STATUS_SUCCESS;
	//&& clear::ClearPfnDatabase() == STATUS_SUCCESS;

	RtlFreeUnicodeString(&driverName);
	return BoolToNt(result);
}

NTSTATUS CreateSharedMemory(SharedMem& mem)
{
	PVOID sharedSection = nullptr;
	HANDLE sectionHandle;
	SECURITY_DESCRIPTOR secDescriptor{};

	extern NTKERNELAPI ERESOURCE PsLoadedModuleResource;

	log(skCrypt("[rwdrv] Creating shared memory\n"));

	auto status = RtlCreateSecurityDescriptor(&secDescriptor, SECURITY_DESCRIPTOR_REVISION);
	if (!NT_SUCCESS(status))
	{
		log(skCrypt("[rwdrv] RtlCreateSecurityDescriptor failed: %lX\n"), status);
		return status;
	}

	log(skCrypt("[rwdrv] Security descriptor created: 0x%p\n"), &secDescriptor);

	const ULONG daclLength = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) * 3 + RtlLengthSid(SeExports->SeLocalSystemSid) +
		RtlLengthSid(SeExports->SeAliasAdminsSid) +
		RtlLengthSid(SeExports->SeWorldSid);

	const auto acl = static_cast<PACL>(ExAllocatePoolWithTag(PagedPool, daclLength, 'lcaD'));

	if (acl == nullptr)
	{
		log(skCrypt("[rwdrv] ExAllocatePoolWithTag failed: %lX\n"), status);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = RtlCreateAcl(acl, daclLength, ACL_REVISION);

	if (!NT_SUCCESS(status))
	{
		ExFreePool(acl);
		log(skCrypt("[rwdrv] RtlCreateAcl failed: %lX\n"), status);
		return status;
	}

	status = RtlAddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, SeExports->SeWorldSid);

	if (!NT_SUCCESS(status))
	{
		ExFreePool(acl);
		log(skCrypt("[rwdrv] RtlAddAccessAllowedAce SeWorldSid failed: %lX\n"), status);
		return status;
	}

	status = RtlAddAccessAllowedAce(acl,
	                                ACL_REVISION,
	                                FILE_ALL_ACCESS,
	                                SeExports->SeAliasAdminsSid);

	if (!NT_SUCCESS(status))
	{
		ExFreePool(acl);
		log(skCrypt("[rwdrv] RtlAddAccessAllowedAce SeAliasAdminsSid failed: %lX\n"), status);
		return status;
	}

	status = RtlAddAccessAllowedAce(acl,
	                                ACL_REVISION,
	                                FILE_ALL_ACCESS,
	                                SeExports->SeLocalSystemSid);

	if (!NT_SUCCESS(status))
	{
		ExFreePool(acl);
		log(skCrypt("[rwdrv] RtlAddAccessAllowedAce SeLocalSystemSid failed: %lX\n"), status);
		return status;
	}

	status = RtlSetDaclSecurityDescriptor(&secDescriptor,
	                                      TRUE,
	                                      acl,
	                                      FALSE);

	if (!NT_SUCCESS(status))
	{
		ExFreePool(acl);
		log(skCrypt("[rwdrv] RtlSetDaclSecurityDescriptor failed: %lX\n"), status);
		return status;
	}

	OBJECT_ATTRIBUTES objAttr{};
	UNICODE_STRING sectionName;
	RtlInitUnicodeString(&sectionName, skCrypt(L"\\BaseNamedObjects\\SysSharedMem"));
	InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE, NULL, &secDescriptor);

	log(skCrypt("[rwdrv] Object created with name %wZ\n"), &sectionName);

	LARGE_INTEGER lMaxSize = {};
	lMaxSize.HighPart = 0;
	lMaxSize.LowPart = 1024 * 10;
	status = ZwCreateSection(&sectionHandle, SECTION_ALL_ACCESS, &objAttr, &lMaxSize, PAGE_READWRITE, SEC_COMMIT, NULL);
	// Create section with section handle, object attributes, and the size of shared mem struct
	if (!NT_SUCCESS(status))
	{
		log(skCrypt("[rwdrv] ZwCreateSection failed: %lX\n"), status);
		return status;
	}

	SIZE_T ulViewSize = 1024 * 10; // &sectionHandle before was here i guess i am correct 
	status = ZwMapViewOfSection(sectionHandle,
	                            ZwCurrentProcess(),
	                            &sharedSection,
	                            0,
	                            ulViewSize,
	                            nullptr,
	                            &ulViewSize,
	                            ViewShare,
	                            0,
	                            PAGE_READWRITE | PAGE_NOCACHE);
	if (!NT_SUCCESS(status))
	{
		log(skCrypt("[rwdrv] ZwMapViewOfSection failed; Status: %lX\n"), status);
		ZwClose(sectionHandle);
		return status;
	}

	log(skCrypt("[rwdrv] Successfully created shared memory section, mapped buffer address [0x%p] \n"), sharedSection);

	ExFreePool(acl);
	// moved this from line : 274 to here 313 its maybe why its causing the error (would be better if i put this in unload driver)

	mem.SectionHandle = sectionHandle;
	mem.SecDescriptor = secDescriptor;
	mem.SharedSection = sharedSection;

	return STATUS_SUCCESS;
}

KSTART_ROUTINE KstartRoutine;

void KstartRoutine(
	void* threadState
)
{
	const auto pDriverState = static_cast<DriverState*>(threadState);
	log(skCrypt("[rwdrv] Thread created, waiting for synchronization\n"));
	LARGE_INTEGER waitInterval;
	waitInterval.QuadPart = 5;
	while (true)
	{
		log("[rwdrv] about to read from [0x%p]\n", pDriverState->Mem.SharedSection);
		DbgBreakPoint();
		KeDelayExecutionThread(KernelMode, false, &waitInterval);
		if (*PULONGLONG(pDriverState->Mem.SharedSection) == ULONGLONG(0xDEADBEEF))
		{
			log(skCrypt("[rwdrv] Thread starting signal received\n"));
			DbgBreakPoint();
			CleanupLoadingTraces(pDriverState);
			log("[rwdrv] Finish!\n");
		}
	}
}

NTSTATUS InitSystemThread(DriverState* driverState)
{
	log(skCrypt("[rwdrv] Creating system thread\n"));
	HANDLE hThread;
	if (PsCreateSystemThread(
		&hThread,
		THREAD_ALL_ACCESS,
		nullptr,
		nullptr,
		nullptr,
		&KstartRoutine,
		static_cast<PVOID>(driverState)
	) != STATUS_SUCCESS)
	{
		log(skCrypt("[rwdrv] Failed to create system thread\n"));
		return STATUS_UNSUCCESSFUL;
	}

	log(skCrypt("[rwdrv] Clearing thread creation traces\n"));

	return BoolToNt(
		clear::UnlinkThread(hThread) == STATUS_SUCCESS
		&& clear::ClearPsPcIdTable(hThread) == STATUS_SUCCESS
	);
}

NTSTATUS
DriverEntry(PVOID baseAddress)
{
	g_DriverState.BaseAddress = baseAddress;

	log(skCrypt("[rwdrv] Driver loaded at [0x%p]\n"), baseAddress);
	return BoolToNt(
		CreateSharedMemory(g_DriverState.Mem) == STATUS_SUCCESS
		&& InitSystemThread(&g_DriverState) == STATUS_SUCCESS
	);
}
