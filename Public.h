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

DEFINE_GUID (GUID_DEVINTERFACE_bettervpn,
    0x9dd9f3bb,0x0e25,0x4d05,0xb3,0x75,0xbc,0x81,0xdc,0x19,0x05,0xf7);
// {9dd9f3bb-0e25-4d05-b375-bc81dc1905f7}
