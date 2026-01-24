#include <initguid.h>
#include "wfp_user_handler.h"
#include <iostream>

#define EXIT_ON_ERROR(x, status, topic) \
    if((status=x) != ERROR_SUCCESS) { \
        std::cout << "Failed Operation detected at " << topic << ". Error Code: " << status << "\n"; \
        goto cleanup; \
    }

// aa952ff1-11ac-4d7b-88f6-6855683a937b
DEFINE_GUID(LAYER_V4_KEY, 0xaa952ff1, 0x11ac, 0x4d7b, 0x88, 0xf6, 0x68, 0x55, 0x68, 0x3a, 0x93, 0x7b);
DEFINE_GUID(CALLOUT_KEY,  0x7c334a77, 0xe480, 0x4a87, 0x87, 0x7a, 0x0e, 0x7f, 0xc8, 0x14, 0x61, 0xe3);
DEFINE_GUID(PROVIDER_KEY,
    0x3437e444,
    0xacf5,
    0x4bdf,
    0x96, 0xa7, 0x31, 0x83, 0x08, 0x38, 0x29, 0xee);
static HANDLE handle = nullptr;



DWORD SetupWFP() {

    DWORD success = ERROR_SUCCESS;
    UINT32 CalloutID = 0;


    wchar_t v6filtername[] = L"v6 bettervpn filter";
    wchar_t v4filtername[] = L"v4 bettervpn filter";

    FWPM_CALLOUT calloutm = { };
    calloutm.displayData.name = v4filtername;
    calloutm.displayData.description = v4filtername;
    calloutm.flags = 0;
    calloutm.calloutKey = CALLOUT_KEY;
    calloutm.applicableLayer = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;

    // one filter is responsible for redirecting IPv4 IPv6 connections to the VPN Server
    // Other filter is responsible for getting the clone the packet data and inject a new packet with encrypted data to the stream
    FWPM_FILTER redirectFilterv4, *lookup_filter;

    EXIT_ON_ERROR(FwpmEngineOpen(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &handle), success, "EngineOpen");
    EXIT_ON_ERROR(FwpmTransactionBegin(handle, 0), success, "TransactionBegin");

    success = FwpmCalloutAdd(handle, &calloutm, NULL, &CalloutID);

    if (success != FWP_E_ALREADY_EXISTS && success != ERROR_SUCCESS) {
        std::cout << "Failed Operation detected at FwpmCalloutAdd Error Code: " << success << "\n";
        goto cleanup;
    }

    RtlZeroMemory(&redirectFilterv4, sizeof(FWPM_FILTER));
    //RtlZeroMemory(&redirectFilterv6, sizeof(FWPM_FILTER));
    //RtlZeroMemory(&packetdataFilter, sizeof(FWPM_FILTER));


    success = FwpmFilterGetByKey(handle, &LAYER_V4_KEY, &lookup_filter);

    // Filter does not exist
    if (success == FWP_E_FILTER_NOT_FOUND) {
        redirectFilterv4.filterKey = LAYER_V4_KEY;
        redirectFilterv4.layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
        redirectFilterv4.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
        redirectFilterv4.action.calloutKey = CALLOUT_KEY;
        redirectFilterv4.weight.type = FWP_EMPTY;
        redirectFilterv4.numFilterConditions = 0;
        redirectFilterv4.displayData.name = v4filtername;
        EXIT_ON_ERROR(FwpmFilterAdd(handle, &redirectFilterv4, NULL, NULL), success, "FilterAdd V4");
    }
    else if (success != ERROR_SUCCESS) { // Error at the method
        std::cout << "Failed Operation detected at FwpmFilterGetByKey Error Code: " << success << "\n";
        goto cleanup;
    }

    FwpmFreeMemory((void**) &lookup_filter);

    /*redirectFilterv6.layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V6;
    redirectFilterv6.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
    redirectFilterv6.action.calloutKey = CALLOUT_KEY;
    redirectFilterv6.weight.type = FWP_EMPTY;
    redirectFilterv6.numFilterConditions = 0;
    redirectFilterv6.displayData.name = v6filtername;
    EXIT_ON_ERROR(FwpmFilterAdd(handle, &redirectFilterv6, NULL, NULL), success, "FilterAdd V6");*/
    EXIT_ON_ERROR(FwpmTransactionCommit(handle), success, "TransactionCommit");

cleanup:
    if (success != ERROR_SUCCESS) {
        FwpmCalloutDeleteByKey(handle, &CALLOUT_KEY);
        FwpmTransactionAbort(handle);
        FwpmEngineClose(handle);
        
        return -1;
    }
    return 0;
}

void CloseWFP() {
    FwpmCalloutDeleteByKey(handle, &CALLOUT_KEY);
    FwpmTransactionAbort(handle);
    FwpmEngineClose(handle);
}