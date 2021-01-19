/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_rwdrv,
    0x58e6ac0d,0xb73f,0x4a05,0x89,0xe2,0xdc,0xe5,0x60,0x01,0xf2,0x86);
// {58e6ac0d-b73f-4a05-89e2-dce56001f286}
