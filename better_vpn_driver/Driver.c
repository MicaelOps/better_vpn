#include "wfp_handler.h"



// User Mode requests an address change for the packet.
#define IOCTL_VPS_SERVER_ADDRESS_CHANGE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Toggle Packet redirection
#define IOCTL_VPS_TOGGLE_REDIRECT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Toggle Packet Encryption
#define IOCTL_VPS_TOGGLE_ENCRYPTION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)


PDEVICE_OBJECT VPNDeviceObject;
UNICODE_STRING DosDeviceName, DeviceName;


// IRP_MJ_CREATE && IRP_MJ_CLOSE Handler Function
static NTSTATUS HandleInitialVPNCommunication(PDEVICE_OBJECT DeviceObject, PIRP irp) {

	NT_ASSERT(DeviceObject);
	NT_ASSERT(irp);

	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(irp);

	DbgPrint("IRP IO Control Code: %ld \n", irpStack->Parameters.DeviceIoControl.IoControlCode);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// IRP_MJ_DEVICE_CONTROL Handler Function
static NTSTATUS HandleVPNControlCommunication(PDEVICE_OBJECT DeviceObject, PIRP irp) {

	NT_ASSERT(DeviceObject);
	NT_ASSERT(irp);

	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(irp);

	
	DbgPrint("IRP IO Control Code: %ld \n", irpStack->Parameters.DeviceIoControl.IoControlCode);

	switch (irpStack->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_VPS_SERVER_ADDRESS_CHANGE:
			
			irp->IoStatus.Status = STATUS_SUCCESS;
			irp->IoStatus.Information = 0;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			break;
		case IOCTL_VPS_TOGGLE_REDIRECT:
			irp->IoStatus.Status = STATUS_SUCCESS;
			irp->IoStatus.Information = 0;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			break;
		case IOCTL_VPS_TOGGLE_ENCRYPTION:
			irp->IoStatus.Status = STATUS_SUCCESS;
			irp->IoStatus.Information = 0;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			break;
	default:
		break;
	}
	return STATUS_SUCCESS;
}

void DriverUnload(PDRIVER_OBJECT DriverObject) {

	UNREFERENCED_PARAMETER(DriverObject);

	closeWFP();

	IoDeleteDevice(VPNDeviceObject);
	DbgPrint("BetterVPN Driver Unloaded \n");
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status = STATUS_SUCCESS;

	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\BetterVPN");
	RtlInitUnicodeString(&DeviceName, L"\\Device\\BetterVPN");

	IoDeleteSymbolicLink(&DosDeviceName);

	DriverObject->DriverUnload = DriverUnload;

	status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &VPNDeviceObject);


	if (!NT_SUCCESS(status)) {
		DbgPrint("Unable to create DeviceObject \n");
		return status;
	}

	status = InitWFP(VPNDeviceObject);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Unable to load InitWFP \n");
		DbgPrint("Error code: %ld", status);
		IoDeleteDevice(VPNDeviceObject);
		return status;
	}

	status = IoCreateSymbolicLink(&DosDeviceName, &DeviceName);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Unable to load create symbolic link Error Code %ld: \n", status);
		IoDeleteSymbolicLink(&DosDeviceName);
		IoDeleteDevice(VPNDeviceObject);
		return status;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = HandleInitialVPNCommunication;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = HandleInitialVPNCommunication;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandleVPNControlCommunication;

	DbgPrint("Driver has been successfully loaded.\n");


	return status;
}