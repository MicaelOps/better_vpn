#include <ntddk.h>
#include "wfp_handler.h"

PDEVICE_OBJECT DeviceObject;


void DriverUnload(PDRIVER_OBJECT DriverObject) {

	UNREFERENCED_PARAMETER(DriverObject);

	closeWFP();

	IoDeleteDevice(DeviceObject);

	DbgPrint("[*] callout driver unloaded\n");
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status = STATUS_SUCCESS;

	status = IoCreateDevice(DriverObject, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

	DriverObject->DriverUnload = DriverUnload;

	if (!NT_SUCCESS(status)) {
		DbgPrint("Unable to create DeviceObject \n");
		return status;
	}

	status = InitWFP(DeviceObject);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Unable to load InitWFP \n");
		goto error;
	}

	DbgPrint("Driver has been successfully loaded.\n");

error:
	DbgPrint("Error code detected %ld", status);

	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(DeviceObject);
	}

	return status;
}