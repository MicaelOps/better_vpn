#include <ntddk.h>
#include "wfp_handler.h"

// User Mode requests an address change for the packet.
#define VPS_SERVER_ADDRESS_CHANGE 0x20

// Toggle Packet redirection
#define VPS_TOGGLE_REDIRECT 0x21

// Toggle Packet Encryption
#define VPS_TOGGLE_ENCRYPTION 0x22

PDEVICE_OBJECT DeviceObject;
UNICODE_STRING DriverSymbolicLink, DriverName;


// IRP_MJ_DEVICE_CONTROL Handler Function
NTSTATUS HandleUserCommunication(PDEVICE_OBJECT DeviceObject, PIRP irp) {

	NT_ASSERT(DeviceObject);
	NT_ASSERT(irp);

	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(irp);

	
	DbgPrint("IRP IO Control Code: %ld", irpStack->Parameters.DeviceIoControl.IoControlCode);

	switch (irpStack->Parameters.DeviceIoControl.IoControlCode) {
		case VPS_SERVER_ADDRESS_CHANGE:
			
			irp->IoStatus.Status = STATUS_SUCCESS;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			break;
		case VPS_TOGGLE_REDIRECT:
			irp->IoStatus.Status = STATUS_SUCCESS;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			break;
		case VPS_TOGGLE_ENCRYPTION:
			irp->IoStatus.Status = STATUS_SUCCESS;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			break;
	default:
		break;
	}

}

void DriverUnload(PDRIVER_OBJECT DriverObject) {

	UNREFERENCED_PARAMETER(DriverObject);

	closeWFP();

	IoDeleteDevice(DeviceObject);

	DbgPrint("[*] callout driver unloaded\n");
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status = STATUS_SUCCESS;

	RtlInitUnicodeString(&DriverSymbolicLink, L"\\??\\BetterVPN");
	RtlInitUnicodeString(&DriverName, L"\\Device\\BetterVPN");

	DriverObject->DriverUnload = DriverUnload;

	status = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);


	if (!NT_SUCCESS(status)) {
		DbgPrint("Unable to create DeviceObject \n");
		return status;
	}

	status = IoCreateSymbolicLink(&DriverSymbolicLink, &DriverName);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Unable to load create symbolic link \n");
		goto error;
	}
	status = InitWFP(DeviceObject);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Unable to load InitWFP \n");
		goto error;
	}

	for (int i = 0; i < 28; ++i) {
		DriverObject->MajorFunction[i] = NULL;
	}

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandleUserCommunication;

	DbgPrint("Driver has been successfully loaded.\n");

error:
	DbgPrint("Error code: %ld", status);
	if (!NT_SUCCESS(status)) {
		IoDeleteSymbolicLink(&DriverSymbolicLink);
		IoDeleteDevice(DeviceObject);
	}

	return status;
}