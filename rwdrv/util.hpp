#pragma once
#include "common.hpp"
#include <ntstrsafe.h>



NTSTATUS ALL_SUCCESS(NTSTATUS status);
template <typename ...A>
__forceinline NTSTATUS ALL_SUCCESS(NTSTATUS status, A ...args);

template NTSTATUS ALL_SUCCESS(NTSTATUS, NTSTATUS);
template NTSTATUS ALL_SUCCESS(NTSTATUS, NTSTATUS, NTSTATUS);
template NTSTATUS ALL_SUCCESS(NTSTATUS, NTSTATUS, NTSTATUS, NTSTATUS);
template NTSTATUS ALL_SUCCESS(NTSTATUS, NTSTATUS, NTSTATUS, NTSTATUS, NTSTATUS);


// NTSTATUS SetupSharedMemory()
// {
// 	log(skCrypt("[rwdrv] Creating shared memory mapping\n"));
//
// 	WinUnicodeString secName{ skCrypt(L"\\BaseNamedObjects\\Global\\IoBufferSection") };
//
// 	CHAR sidBuffer[SECURITY_MAX_SID_SIZE];
// 	ULONG sidSize = 0;
// 	ACL daclSet;
// 	SECURITY_DESCRIPTOR SecDescriptor;
// 	HANDLE sectionHandle;
// 	// #define SHARED_MEMORY 0x100
//
//
// 	auto status = SecLookupWellKnownSid(WinBuiltinAdministratorsSid, &sidBuffer, sizeof(sidBuffer), &sidSize);
// 	// Looks up for administrator account SID and returns to buffer
// 	if (!NT_SUCCESS(status))
// 	{
// 		log(skCrypt("[rwdrv] SecLookupWellKnownSid failed\n"));
// 		return status;
// 	}
// 	auto _sidSize = RtlLengthSid(&sidBuffer); // Get size of SID we want to add to DACL
// 	ACCESS_ALLOWED_ACE _testing; // Allocate structure for sizing
// 	ULONG _sidstartSize = sizeof(_testing.SidStart); //Get size of ULONG SidStart in ACCESS_ALLOWED_ACE
// 	ULONG _ACLSize = sizeof(ACCESS_ALLOWED_ACE) - _sidstartSize + _sidSize; // Calculate full ACL size for ACL
// 	status = RtlCreateAcl(&daclSet, _ACLSize + 0x10, ACL_REVISION); //Create ACL using the ACL size
// 	if (!NT_SUCCESS(status))
// 	{
// 		log(skCrypt("[rwdrv] RtlCreateAcl failed\n"));
// 		return status;
// 	}
// 	status = RtlAddAccessAllowedAce(&daclSet, ACL_REVISION, FILE_ALL_ACCESS, &sidBuffer); //Add SID to ACL
// 	if (!NT_SUCCESS(status))
// 	{
// 		log(skCrypt("[rwdrv] RtlAddAccessAllowedAce failed\n"));
// 		return status;
// 	}
// 	status = RtlCreateSecurityDescriptor(&SecDescriptor, SECURITY_DESCRIPTOR_REVISION); //Initialize Security Descriptor
// 	if (!NT_SUCCESS(status))
// 	{
// 		log(skCrypt("[rwdrv] RtlCreateSecurityDescriptor failed\n"));
// 		return status;
// 	}
// 	status = RtlSetDaclSecurityDescriptor(&SecDescriptor, FALSE, &daclSet, TRUE); //Add DACL to Security Descriptor
// 	if (!NT_SUCCESS(status))
// 	{
// 		log(skCrypt("[rwdrv] RtlSetDaclSecurityDescriptor failed\n"));
// 		return status;
// 	}
// 	OBJECT_ATTRIBUTES objAttr; //Allocate object attribute structure
//
// 	InitializeObjectAttributes(&objAttr, secName.Raw(), OBJ_CASE_INSENSITIVE, NULL, &SecDescriptor);
// 	// Initialize OBJECT_ATTRIBUTES using section name and security descriptor
//
// 	g::DriverState.SharedMemory.RealSize = 1024 * 4;
//
// 	LARGE_INTEGER maxSize; // Allocate max size structure
// 	maxSize.QuadPart = g::DriverState.SharedMemory.RealSize;
//
// 	status = ZwCreateSection(&sectionHandle, SECTION_ALL_ACCESS, &objAttr, &maxSize, PAGE_READWRITE, SEC_COMMIT, NULL);
// 	// Create section with section handle, object attributes, and the size of shared mem struct
// 	if (!NT_SUCCESS(status))
// 	{
// 		log(skCrypt("[rwdrv] ZwCreateSection failed\n"));
// 		return status;
// 	}
//
// 	PVOID secBaseAddress;
//
// 	status = ZwMapViewOfSection(
// 		sectionHandle,
// 		ZwCurrentProcess(),
// 		&secBaseAddress,
// 		NULL,
// 		maxSize.QuadPart,
// 		nullptr,
// 		&g::DriverState.SharedMemory.RealSize,
// 		ViewShare,
// 		0,
// 		PAGE_READWRITE | PAGE_NOCACHE
// 	);
//
// 	if (!NT_SUCCESS(status))
// 	{
// 		log(skCrypt("[rwdrv] ZwMapViewOfSection failed\n"));
// 		return status;
// 	}
//
// 	g::DriverState.SharedMemory.SectionHandle = sectionHandle;
// 	g::DriverState.SharedMemory.SectionAddress = secBaseAddress;
// 	g::DriverState.SharedMemory.MaxSize = maxSize.QuadPart;
//
// 	log(skCrypt("[rwdrv] Successfully opened shared memory at %wZ\n"), secName.Raw());
//
// 	return STATUS_SUCCESS;
// }