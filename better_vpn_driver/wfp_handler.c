
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


typedef struct {
	IN_ADDR address;
	USHORT port;
} ADDR_PORT;


typedef struct _REDIRECTION_CONTEXT {
	RTL_DYNAMIC_HASH_TABLE_ENTRY structEntry;
	ADDR_PORT original_address;
	ULONG tag;

} REDIRECTION_CONTEXT, *PREDIRECTION_CONTEXT;

typedef struct {
	PVOID buf;
	PMDL mdl;
	PNET_BUFFER_LIST nbl;
	ULONG tag;
} INJECT_CONTEXT, *PINJECT_CONTEXT;

const ULONG headersize = sizeof(ADDR_PORT);

const GUID REDIRECT_CALLOUT_KEY = { 0x7c334a77,
							0xe480,
							0x4a87,
							0x87, 0x7a, 0x0e, 0x7f, 0xc8, 0x14, 0x61, 0xe3};

//9a40acb5-2683-464e-9a96-3c6fc9bbb34a

const GUID STREAM_CALLOUT_KEY = {  0x9a40acb5,
							0x2683,
							0x464e,
							0x9a, 0x96, 0x3c, 0x6f, 0xc9, 0xbb, 0xb3, 0x4a };

const GUID PROVIDER_KEY = {
	0x3437e444,
	0xacf5,
	0x4bdf,
	0x96, 0xa7, 0x31, 0x83, 0x08, 0x38, 0x29, 0xee };

PRTL_DYNAMIC_HASH_TABLE context_manager;

NDIS_HANDLE ndisPool = NULL;
HANDLE RedirectHandle = NULL, InjectionHandle = NULL;

UINT32 RedirectCalloutId = 0, StreamCalloutId = 0;
ULONG tagcounter = 230L;
BOOL redirecting = TRUE;
SOCKADDR_STORAGE currProxyServer = { 0 };


VOID CleanupHashTable()
{
	RTL_DYNAMIC_HASH_TABLE_ENUMERATOR enumerator;
	RtlInitEnumerationHashTable(context_manager, &enumerator);

	PRTL_DYNAMIC_HASH_TABLE_ENTRY entry;

	while ((entry = RtlEnumerateEntryHashTable(context_manager, &enumerator)) != NULL) {

		PREDIRECTION_CONTEXT context = CONTAINING_RECORD(entry, REDIRECTION_CONTEXT, structEntry);

		RtlRemoveEntryHashTable(context_manager, entry, NULL);
		ExFreePoolWithTag(context, context->tag);
	}
	RtlEndEnumerationHashTable(context_manager, &enumerator);
	RtlDeleteHashTable(context_manager);
}


void CompleteInjectionHeader(
	void* context,
	NET_BUFFER_LIST* netBufferList,
	BOOLEAN dispatchLevel) {

	UNREFERENCED_PARAMETER(context);
	UNREFERENCED_PARAMETER(netBufferList);
	UNREFERENCED_PARAMETER(dispatchLevel);

	PINJECT_CONTEXT ctx = (PINJECT_CONTEXT) context;
	IoFreeMdl(ctx->mdl);
	ExFreePoolWithTag(ctx->buf, (ctx->tag-333333) + 1000); // THIS IS SO STUPID BTW, WHY AM I NOT STORING TAG WITHOUT THE INCREMENTS? BUT I AM TOO LAZY RN!
	NdisFreeNetBufferList(ctx->nbl);
	ExFreePoolWithTag(ctx, ctx->tag);
}

void CompleteInjection(
	 void* context,
	 NET_BUFFER_LIST* netBufferList,
	 BOOLEAN dispatchLevel) {

	UNREFERENCED_PARAMETER(context);
	UNREFERENCED_PARAMETER(netBufferList);
	UNREFERENCED_PARAMETER(dispatchLevel);

	FwpsFreeCloneNetBufferList(netBufferList, 0);
}


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
			/*DbgPrint(
				"IP Address %u.%u.%u.%u Port %u\n",
				(unsigned int)sin->sin_addr.S_un.S_un_b.s_b1,
				(unsigned int)sin->sin_addr.S_un.S_un_b.s_b2,
				(unsigned int)sin->sin_addr.S_un.S_un_b.s_b3,
				(unsigned int)sin->sin_addr.S_un.S_un_b.s_b4,
				correct_port
			);*/
			

			// Checking if we have a valid proxyServer and we are redirecting
			// Also checking that we do not change the DNS functionalities
			if (currProxyServer.ss_family == AF_INET && ( correct_port == 443 || correct_port == 80) ) {
				DbgPrint("Packet redirected?! \n");
				DbgPrint("IRQL at allocation: %d\n", KeGetCurrentIrql());
				PREDIRECTION_CONTEXT context = ExAllocatePool2(NonPagedPool, sizeof(REDIRECTION_CONTEXT), 'xCta');

				if (!context) {
					DbgPrint("Unable to allocate Redirection Context to packet.");
					FwpsReleaseClassifyHandle(ClassifyHandle);
					return;
				}
				DbgPrint("Redirection Context Alocated succesfully ");
				ADDR_PORT addr = { sin->sin_addr, correct_port };
				context->original_address = addr;
				context->tag = 'xCta';

				tagcounter++;

				RtlCopyMemory(&connectRequest->remoteAddressAndPort, &currProxyServer, sizeof(SOCKADDR_IN));

				RtlInsertEntryHashTable(context_manager, &context->structEntry, inMetaValues->flowHandle, NULL);

				// Verify what was actually written yes
				/*DbgPrint("AFTER COPY: %u.%u.%u.%u:%u\n",
					sin->sin_addr.S_un.S_un_b.s_b1,
					sin->sin_addr.S_un.S_un_b.s_b2,
					sin->sin_addr.S_un.S_un_b.s_b3,
					sin->sin_addr.S_un.S_un_b.s_b4,
					RtlUshortByteSwap(sin->sin_port));*/
			}

			FwpsApplyModifiedLayerData(ClassifyHandle, writableLayerData, 0);
			
			FwpsReleaseClassifyHandle(ClassifyHandle);
		}

	}
	else if (inFixedValues->layerId == FWPS_LAYER_STREAM_V4) {

		if (filter->action.type == FWP_ACTION_BLOCK) 
			return;
		
		FWPS_STREAM_CALLOUT_IO_PACKET* packet = (FWPS_STREAM_CALLOUT_IO_PACKET*)layerData;

		if (packet->streamData->flags != FWPS_STREAM_FLAG_SEND)
			return;

		FWPS_PACKET_INJECTION_STATE state = FwpsQueryPacketInjectionState(InjectionHandle, packet->streamData->netBufferListChain, NULL);

		if (state == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF || state == FWPS_PACKET_INJECTED_BY_SELF)
			return;

		PRTL_DYNAMIC_HASH_TABLE_ENTRY entry = RtlLookupEntryHashTable(context_manager, inMetaValues->flowHandle, NULL);

		if (entry) {

			// To prepend our header [ original_address + port ] we need to inject first our bits and then send the original data back.

			PREDIRECTION_CONTEXT context = CONTAINING_RECORD(entry, REDIRECTION_CONTEXT, structEntry);
			PNET_BUFFER_LIST header_net_buffer_list = NULL;
			NTSTATUS status = ERROR_SEVERITY_SUCCESS;
			classifyOut->actionType = FWP_ACTION_BLOCK;
			packet->countBytesEnforced = packet->streamData->dataLength;


			// really bad tagcounter but i cba at this point, user project
			PVOID buf = ExAllocatePool2(NonPagedPool, headersize, 'fuBa');

			if (!buf) {
				DbgPrint("Unable to allocate buff for injection \n");
				return;
			}

			RtlCopyMemory(buf, &context->original_address, headersize);

			PMDL mdl = IoAllocateMdl(buf, headersize, FALSE, FALSE, NULL);

			if (!mdl) {
				DbgPrint("Injection done incorrectly at mdl \n");
				goto error;
			}
			MmBuildMdlForNonPagedPool(mdl);


			classifyOut->actionType = FWP_ACTION_BLOCK;
			packet->countBytesEnforced = packet->streamData->dataLength;


			header_net_buffer_list =
				NdisAllocateNetBufferAndNetBufferList(
					ndisPool,
					0,
					0,
					mdl,
					0,
					headersize
				);

			if (!header_net_buffer_list) {
				DbgPrint("Injection done incorrectly at NdisAllocateNetBufferAndNetBufferList \n");
				goto error;
			}

			/* Inject the new bits first */
			INJECT_CONTEXT* injectCtx = ExAllocatePool2(NonPagedPool, sizeof(INJECT_CONTEXT), 'fyba');


			if (!injectCtx) {
				DbgPrint("Injection done incorrectly at injectCtx ExAllocatePool2 \n");
				goto error;
			}

			injectCtx->buf = buf;
			injectCtx->mdl = mdl;
			injectCtx->nbl = header_net_buffer_list;
			injectCtx->tag = 'fyba';

			status = FwpsStreamInjectAsync0(
				InjectionHandle,
				NULL,
				0,
				inMetaValues->flowHandle,
				StreamCalloutId,
				inFixedValues->layerId,
				FWPS_STREAM_FLAG_SEND,
				header_net_buffer_list,
				headersize,
				CompleteInjectionHeader,
				injectCtx
			);


			if (!NT_SUCCESS(status)) {
				DbgPrint("Injection done incorrectly at FwpsStreamInjectAsync0 1. \n");
				goto error;
			}
			/* Injecting the original data */


			PNET_BUFFER_LIST bufferlist;

			status = FwpsCloneStreamData0(packet->streamData, NULL, NULL, 0, &bufferlist);

			// SIGH I WILL DO THE MACRO LATER !
			if (!NT_SUCCESS(status)) {
				DbgPrint("Injection done incorrectly at FwpsCloneStreamData. \n");
				goto error;
			}
			

			status = FwpsStreamInjectAsync(
				InjectionHandle,
				NULL,
				0,
				inMetaValues->flowHandle,
				StreamCalloutId,
				inFixedValues->layerId,
				FWPS_STREAM_FLAG_SEND,
				bufferlist,
				packet->streamData->dataLength,
				CompleteInjection,
				context
			);

		error:

			if (!NT_SUCCESS(status)) {

				if(mdl)
					IoFreeMdl(mdl);

				ExFreePoolWithTag(buf, 'fyba');

				if(header_net_buffer_list)
					NdisFreeNetBufferList(header_net_buffer_list);

				DbgPrint("Unable to clone stream data %ld \n", status);
				return;
			}
			DbgPrint("Injection done successfully. \n");

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
	
	if (RedirectCalloutId == 0)
		return status;

	FwpsInjectionHandleDestroy(InjectionHandle);
	FwpsRedirectHandleDestroy(RedirectHandle);

	status = FwpsCalloutUnregisterById(RedirectCalloutId);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Unable to unregister VPN Callout. \n");
		return status;
	}

	status = FwpsCalloutUnregisterById(StreamCalloutId);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Unable to unregister VPN Callout. \n");
		return status;
	}

	CleanupHashTable();

	if (ndisPool)
		NdisFreeNetBufferListPool(ndisPool);

	return STATUS_SUCCESS;
}

NTSTATUS InitWFP(PDEVICE_OBJECT DeviceObject) {
	NTSTATUS status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(DeviceObject);

	NET_BUFFER_LIST_POOL_PARAMETERS params = { 0 };
	params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
	params.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
	params.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
	params.fAllocateNetBuffer = TRUE;
	params.PoolTag = 'iool';
	params.DataSize = 0;

	DbgPrint("Header size %ld \n", headersize);

	ndisPool = NdisAllocateNetBufferListPool(NULL, &params);

	if (ndisPool == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DbgPrint("Unable to allocate NdisAllocateNetBufferListPool \n");
		goto error;
	}

	RtlCreateHashTable(&context_manager, 4, 0);
	
	FWPS_CALLOUT RedirectCallout = {
			REDIRECT_CALLOUT_KEY,
			0,
			ClassifyFn,
			NotifyFn,
			FlowDeleteFn };

	FWPS_CALLOUT StreamCallout = {
		STREAM_CALLOUT_KEY,
		0,
		ClassifyFn,
		NotifyFn,
		FlowDeleteFn };

	// Registering the callout.
	status = FwpsCalloutRegister(DeviceObject, &RedirectCallout, &RedirectCalloutId);
	

	if (!NT_SUCCESS(status)) {
		DbgPrint("Unable to load FwpsCalloutRegister RedirectCallout, Error: %ld \n", status);
		goto error;
	}

	// Registering the callout.
	status = FwpsCalloutRegister(DeviceObject, &StreamCallout, &StreamCalloutId);


	if (!NT_SUCCESS(status)) {
		DbgPrint("Unable to load FwpsCalloutRegister StreamCallout, Error: %ld \n", status);
		goto error;
	}

	status = FwpsInjectionHandleCreate(AF_INET, FWPS_INJECTION_TYPE_STREAM, &InjectionHandle);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Unable to load FwpsInjectionHandleCreate, Error: %ld \n", status);
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
		FwpsCalloutUnregisterById(RedirectCalloutId);
		FwpsCalloutUnregisterById(StreamCalloutId);
		return status;
	}

	return STATUS_SUCCESS;
}

// IRP_MJ_DEVICE_CONTROL Handler Function
NTSTATUS HandleVPNControlCommunication(PDEVICE_OBJECT DeviceObject, PIRP irp) {

	NT_ASSERT(DeviceObject);
	NT_ASSERT(irp);

	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(irp);


	DbgPrint("WFP IRP IO Control Code: %ld \n", irpStack->Parameters.DeviceIoControl.IoControlCode);

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
		irp->IoStatus.Status = STATUS_SUCCESS;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		break;
	}
	return STATUS_SUCCESS;
}
