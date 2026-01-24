
#include "wfp_handler.h"
#include <ntstrsafe.h>

// User Mode requests an address change for the packet.
#define IOCTL_VPS_SERVER_ADDRESS_CHANGE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Toggle Packet redirection
#define IOCTL_VPS_TOGGLE_REDIRECT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Toggle Packet Encryption
#define IOCTL_VPS_TOGGLE_ENCRYPTION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

const GUID CALLOUT_KEY = { 0x7c334a77,
							0xe480,
							0x4a87,
							0x87, 0x7a, 0x0e, 0x7f, 0xc8, 0x14, 0x61, 0xe3};

const GUID PROVIDER_KEY = {
	0x3437e444,
	0xacf5,
	0x4bdf,
	0x96, 0xa7, 0x31, 0x83, 0x08, 0x38, 0x29, 0xee };

UINT32 CalloutId = 0;
HANDLE RedirectHandle = NULL;
BOOL redirecting = TRUE;
SOCKADDR_STORAGE currProxyServer = { 0 };



// The callback function where the filtering logic is implemented.
// Inline Modification Callout
static VOID NTAPI ClassifyFn(
	IN const FWPS_INCOMING_VALUES* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	IN OUT VOID* layerData,
	IN const VOID* classifyContext,
	IN const FWPS_FILTER* filter,
	IN UINT64  flowContext,
	IN OUT FWPS_CLASSIFY_OUT* classifyOut
) {
	UNREFERENCED_PARAMETER(inFixedValues);
	UNREFERENCED_PARAMETER(inMetaValues);
	UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(classifyOut);

	if (filter == NULL) 
		return;
	
	if (inFixedValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4) {
		if (filter->action.type != FWP_ACTION_BLOCK) {
			// Checking if the Filter has already been previously redirected by our callout driver
			FWPS_CONNECTION_REDIRECT_STATE redirectState = FwpsQueryConnectionRedirectState(inMetaValues->redirectRecords, RedirectHandle, NULL);

			if (redirectState != FWPS_CONNECTION_NOT_REDIRECTED || !redirecting)
				return;

			UINT64 ClassifyHandle;
			NTSTATUS status = FwpsAcquireClassifyHandle((void*)classifyContext, 0, &ClassifyHandle);

			if (!NT_SUCCESS(status)) {
				DbgPrint("Unable to FwpsAcquireClassifyHandle. Error Code: %ld", status);
				return;
			}

			PVOID writableLayerData;
			status = FwpsAcquireWritableLayerDataPointer(ClassifyHandle, filter->filterId, 0, &writableLayerData, classifyOut);


			if (!NT_SUCCESS(status)) {
				DbgPrint("Unable to FwpsAcquireWritableLayerDataPointer. Error Code: %ld", status);
				return;
			}

			
			FWPS_CONNECT_REQUEST* connectRequest = (FWPS_CONNECT_REQUEST*) writableLayerData;
			SOCKADDR_IN* sin = (SOCKADDR_IN*) &connectRequest->remoteAddressAndPort;

			// CORRECT ENDIANESS
			USHORT correct_port = RtlUshortByteSwap(sin->sin_port);
			DbgPrint(
				"IP Address %u.%u.%u.%u Port %u\n",
				(unsigned int)sin->sin_addr.S_un.S_un_b.s_b1,
				(unsigned int)sin->sin_addr.S_un.S_un_b.s_b2,
				(unsigned int)sin->sin_addr.S_un.S_un_b.s_b3,
				(unsigned int)sin->sin_addr.S_un.S_un_b.s_b4,
				correct_port
			);
			

			// Checking if we have a valid proxyServer and we are redirecting
			// Also checking that we do not change the DNS functionalities
			if (currProxyServer.ss_family == AF_INET && correct_port != 53 && correct_port != 5353 && correct_port != 138) {
				DbgPrint("Packet redirected?! \n");
				
				RtlCopyMemory(&connectRequest->remoteAddressAndPort, &currProxyServer, sizeof(SOCKADDR_IN));
				// Verify what was actually written
				DbgPrint("AFTER COPY: %u.%u.%u.%u:%u\n",
					sin->sin_addr.S_un.S_un_b.s_b1,
					sin->sin_addr.S_un.S_un_b.s_b2,
					sin->sin_addr.S_un.S_un_b.s_b3,
					sin->sin_addr.S_un.S_un_b.s_b4,
					RtlUshortByteSwap(sin->sin_port));
			}

			FwpsApplyModifiedLayerData(ClassifyHandle, writableLayerData, 0);
			
			FwpsReleaseClassifyHandle(ClassifyHandle);
		}

	}
}

// Called whenever a filter that references the callout is added or removed. 
static NTSTATUS NTAPI NotifyFn(
	IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	IN const GUID* filterKey,
	IN const FWPS_FILTER* filter
) {
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	NT_ASSERT(filter);

	DbgPrint("Some filter is being added?? \n");
	switch (notifyType) {
		case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
		case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
	default:
		break;
	}
	return STATUS_SUCCESS;
}

static VOID NTAPI FlowDeleteFn(
	IN UINT16  layerId,
	IN UINT32  calloutId,
	IN UINT64  flowContext
) {
	UNREFERENCED_PARAMETER(layerId);
	UNREFERENCED_PARAMETER(calloutId);
	UNREFERENCED_PARAMETER(flowContext);

	DbgPrint("Some filter is being DELETED?? \n");
}



NTSTATUS closeWFP(VOID) {
	NTSTATUS status = STATUS_SUCCESS;
	
	if (CalloutId == 0)
		return status;

	FwpsRedirectHandleDestroy(RedirectHandle);

	status = FwpsCalloutUnregisterById(CalloutId);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Unable to unregister VPN Callout. \n");
		return status;
	}


	return STATUS_SUCCESS;
}

NTSTATUS InitWFP(PDEVICE_OBJECT DeviceObject) {
	NTSTATUS status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(DeviceObject);

	FWPS_CALLOUT Callout = {
			CALLOUT_KEY,
			0,
			ClassifyFn,
			NotifyFn,
			FlowDeleteFn};

	// Registering the callout.
	status = FwpsCalloutRegister(DeviceObject, &Callout, &CalloutId);
	

	if (!NT_SUCCESS(status)) {
		DbgPrint("Unable to load FwpsCalloutRegister, Error: %ld \n", status);
		goto error;
	}


	status = FwpsRedirectHandleCreate(&PROVIDER_KEY,0,&RedirectHandle);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Unable to load FwpsRedirectHandleCreate, Error: %ld \n", status);
		goto error;
	}

	DbgPrint("Sucessfully opened the engine; \n");

error:
	if (!NT_SUCCESS(status)) {
		FwpsCalloutUnregisterById(CalloutId);
		return status;
	}

	return STATUS_SUCCESS;
}

// IRP_MJ_DEVICE_CONTROL Handler Function
NTSTATUS HandleVPNControlCommunication(PDEVICE_OBJECT DeviceObject, PIRP irp) {

	NT_ASSERT(DeviceObject);
	NT_ASSERT(irp);

	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(irp);


	DbgPrint("IRP IO Control Code: %ld \n", irpStack->Parameters.DeviceIoControl.IoControlCode);

	switch (irpStack->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_VPS_SERVER_ADDRESS_CHANGE:
		irp->IoStatus.Status = STATUS_SUCCESS;
		irp->IoStatus.Information = 0;

		ULONG size = irpStack->Parameters.DeviceIoControl.InputBufferLength;
		void* buf = irp->AssociatedIrp.SystemBuffer;

		DbgPrint("Received IOCTL_VPS_SERVER_ADDRESS_CHANGE call with size %ld \n", size);
		if (size >= sizeof(SOCKADDR_IN)) {
			RtlZeroMemory(&currProxyServer, sizeof(currProxyServer));
			RtlCopyMemory(&currProxyServer, buf, sizeof(SOCKADDR_IN));

			SOCKADDR_IN* sin = (SOCKADDR_IN*)&currProxyServer;
			USHORT correct_port = RtlUshortByteSwap(sin->sin_port);

			DbgPrint(
				"IOCTL_VPS_SERVER_ADDRESS_CHANGE Proxy Server %u.%u.%u.%u Port %u\n",
				(unsigned int)sin->sin_addr.S_un.S_un_b.s_b1,
				(unsigned int)sin->sin_addr.S_un.S_un_b.s_b2,
				(unsigned int)sin->sin_addr.S_un.S_un_b.s_b3,
				(unsigned int)sin->sin_addr.S_un.S_un_b.s_b4,
				correct_port
			);

		}
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		break;
	case IOCTL_VPS_TOGGLE_REDIRECT:
		DbgPrint("IOCTL_VPS_TOGGLE_REDIRECT call received value of redirecting %d \n", redirecting);
		redirecting = !redirecting;
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
