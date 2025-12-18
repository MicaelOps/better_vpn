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


typedef struct TESTSOCKADDR {
	unsigned short family;
	char data[14];
} *PTESTSOCKADDR;

DEFINE_GUID(

	PROVIDER_KEY,
	0x3437e444,
	0xacf5,
	0x4bdf,
	0x96, 0xa7, 0x31, 0x83, 0x08, 0x38 0x29, 0xee
);

UINT32 CalloutId = 0;
HANDLE RedirectHandle = NULL;
struct TESTSOCKADDR currProxyServer;



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
	
	if (inFixedValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4 || inFixedValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V6) {

		if (filter->action.type == FWP_ACTION_PERMIT) {

			// Checking if the Filter has already been previously redirected by our callout driver
			FWPS_CONNECTION_REDIRECT_STATE redirectState = FwpsQueryConnectionRedirectState(inMetaValues->redirectRecords, RedirectHandle, NULL);

			if (redirectState == FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF || redirectState == FWPS_CONNECTION_REDIRECTED_BY_SELF)
				return;

			
			UINT64 ClassifyHandle;
			NTSTATUS status = FwpsAcquireClassifyHandle(classifyContext, 0, &ClassifyHandle);

			if (!NT_SUCCESS(status)) {
				DbgPrint("Unable to FwpsAcquireClassifyHandle. Error Code: %ld", status);
				return;
			}

			FWPS_CLASSIFY_OUT ClassifyOut;
			PVOID writableLayerData;
			status = FwpsAcquireWritableLayerDataPointer(ClassifyHandle, filter->filterId, 0, &writableLayerData, &ClassifyOut);

			FWPS_CONNECT_REQUEST* connectRequest = (FWPS_CONNECT_REQUEST*) writableLayerData;
			connectRequest->localAddressAndPort = (SOCKADDR_STORAGE) currProxyServer;

			
			
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
}

const FWPS_CALLOUT Callout = {
	{ 0x7c334a77, 0xe480, 0x4a87, { 0x87, 0x7a, 0x0e, 0x7f, 0xc8, 0x14, 0x61, 0xe3 } },
	0,
	ClassifyFn,
	NotifyFn,
	FlowDeleteFn
};


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

	// Registering the callout.
	status = FwpsCalloutRegister(DeviceObject, &Callout, &CalloutId);


	if (!NT_SUCCESS(status)) {
		DbgPrint("Unable to load FwpmEngineOpen, Error: %ld \n", status);
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
		void* buf = irp->UserBuffer;

		DbgPrint("Received IOCTL_VPS_SERVER_ADDRESS_CHANGE call with size %ld ", size);

		if(size >= sizeof(currProxyServer))
			RtlCopyMemory((void*)&currProxyServer, buf, sizeof(currProxyServer));

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
