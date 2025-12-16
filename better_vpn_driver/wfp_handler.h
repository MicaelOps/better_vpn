#pragma once

#define NDIS630
#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ws2ipdef.h>

NTSTATUS closeWFP(VOID);
NTSTATUS InitWFP(PDEVICE_OBJECT DeviceObject);