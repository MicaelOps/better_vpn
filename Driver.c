#include <ntddk.h>
#include "wfp_handler.h"

// User Mode requests an address change for the packet.
#define VPS_SERVER_ADDRESS_CHANGE 0x20

// Toggle Packet redirection
#define VPS_TOGGLE_REDIRECT 0x21

// Toggle Packet Encryption
#define VPS_TOGGLE_ENCRYPTION 0x22

PDEVICE_OBJECT DeviceObject;
UNICODE_STRING DosDeviceName, DeviceName;


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

	DbgPrint("BetterVPN Driver Unloaded \n");
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status = STATUS_SUCCESS;

	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\BetterVPN");
	RtlInitUnicodeString(&DeviceName, L"\\Device\\BetterVPN");

	DriverObject->DriverUnload = DriverUnload;


	status = IoCreateSymbolicLink(&DosDeviceName, &DeviceName);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Unable to load create symbolic link \n");
		return status;
	}

	status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);


	if (!NT_SUCCESS(status)) {
		DbgPrint("Unable to create DeviceObject \n");
		IoDeleteSymbolicLink(&DosDeviceName);
		return status;
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
	if (!NT_SUCCESS(status)) {
		DbgPrint("Error code: %ld", status);
		IoDeleteSymbolicLink(&DosDeviceName);
		IoDeleteDevice(DeviceObject);
	}

	return status;
}