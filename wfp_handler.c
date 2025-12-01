#include "wfp_handler.h"

UINT32 CalloutId = NULL;

const FWPS_CALLOUT Callout = {
	{ 0x7c334a77, 0xe480, 0x4a87, { 0x87, 0x7a, 0x0e, 0x7f, 0xc8, 0x14, 0x61, 0xe3 } },
	0,
	ClassifyFn,
	NotifyFn,
	FlowDeleteFn
};

// The callback function where the filtering logic is implemented.
// Inline Modification Callout
VOID NTAPI ClassifyFn(
	IN const FWPS_INCOMING_VALUES* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	IN OUT VOID* layerData,
	IN const FWPS_FILTER* filter,
	IN UINT64  flowContext,
	IN OUT FWPS_CLASSIFY_OUT* classifyOut
) {
	
}

// Called whenever a filter that references the callout is added or removed. 
NTSTATUS NTAPI NotifyFn(
	IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	IN const GUID* filterKey,
	IN const FWPS_FILTER* filter
) {

	NT_ASSERT(filter);

	switch (notifyType) {
		case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
		case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
	default:
		break;
	}
	return STATUS_SUCCESS;
}

VOID NTAPI FlowDeleteFn(
	IN UINT16  layerId,
	IN UINT32  calloutId,
	IN UINT64  flowContext
) {

}



NTSTATUS closeWFP() {
	NTSTATUS status = STATUS_SUCCESS;

	if (CalloutId != NULL) {

		status = FwpsCalloutUnregisterById(CalloutId);


	}

	return status;
}

NTSTATUS InitWFP(PDEVICE_OBJECT DeviceObject) {
	NTSTATUS status = STATUS_SUCCESS;

	// Registering the callout.
	status = FwpsCalloutRegister(DeviceObject, &Callout, &CalloutId);


	if (!NT_SUCCESS(status)) {
		DbgPrint("Unable to load FwpmEngineOpen \n");
		goto error;
	}

	DbgPrint("Sucessfully opened the engine; \n");

error:
	if (!NT_SUCCESS(status)) {

	}

	return status;
}