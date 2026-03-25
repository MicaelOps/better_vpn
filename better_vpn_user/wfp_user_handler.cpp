#include <initguid.h>
#include "wfp_user_handler.h"
#include <iostream>

#define EXIT_ON_ERROR(x, status, topic) \
    if((status=x) != ERROR_SUCCESS) { \
        std::cout << "Failed Operation detected at " << topic << ". Error Code: " << status << "\n"; \
        goto cleanup; \
    }


#define EXIT_ON_ERROR_CUSTOM(status, topic) \
    if(status) { \
        std::cout << "Failed Operation detected at " << topic << ". \n"; \
        goto cleanup; \
    }

DEFINE_GUID(LAYER_STREAM_V4_KEY, 0x82b1bb74, 0xcc17, 0x4261, 0x88, 0xca, 0x9a, 0xf5, 0xa9, 0x91, 0xca, 0x1e);
DEFINE_GUID(LAYER_REDIRECT_V4_KEY, 0xaa952ff1, 0x11ac, 0x4d7b, 0x88, 0xf6, 0x68, 0x55, 0x68, 0x3a, 0x93, 0x7b);
DEFINE_GUID(REDIRECT_CALLOUT_KEY,  0x7c334a77, 0xe480, 0x4a87, 0x87, 0x7a, 0x0e, 0x7f, 0xc8, 0x14, 0x61, 0xe3);
DEFINE_GUID(PROVIDER_KEY,0x3437e444, 0xacf5,0x4bdf, 0x96, 0xa7, 0x31, 0x83, 0x08, 0x38, 0x29, 0xee);
DEFINE_GUID(STREAM_CALLOUT_KEY, 0x9a40acb5, 0x2683, 0x464e, 0x9a, 0x96, 0x3c, 0x6f, 0xc9, 0xbb, 0xb3, 0x4a);

static HANDLE handle = nullptr;



DWORD SetupWFP() {

    DWORD success = ERROR_SUCCESS;
    UINT32 RedirectCalloutID = 0, StreamCalloutID = 0;


    wchar_t streamcallout[] = L"v4 bettervpn stream filter";
    wchar_t v4filtername[] = L"v4 bettervpn filter";

    FWPM_CALLOUT redirect_callout{ 0 }, stream_callout{ 0 };

    redirect_callout.displayData.name = v4filtername;
    redirect_callout.displayData.description = v4filtername;
    redirect_callout.flags = 0;
    redirect_callout.calloutKey = REDIRECT_CALLOUT_KEY;
    redirect_callout.applicableLayer = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;

    stream_callout.displayData.name = streamcallout;
    stream_callout.displayData.description = streamcallout;
    stream_callout.flags = 0;
    stream_callout.calloutKey = STREAM_CALLOUT_KEY;
    stream_callout.applicableLayer = FWPM_LAYER_STREAM_V4;
    

    // one filter is responsible for redirecting IPv4 IPv6 connections to the VPN Server
    // Other filter is responsible for getting the clone the packet data and inject a new packet with encrypted data to the stream
    FWPM_FILTER redirectFilterv4 {0}, streamDatav4 {0}, * lookup_filter = nullptr, * stream_filter_lookup = nullptr;
    EXIT_ON_ERROR(FwpmEngineOpen(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &handle), success, "EngineOpen");
    EXIT_ON_ERROR(FwpmTransactionBegin(handle, 0), success, "TransactionBegin");
    success = FwpmCalloutAdd(handle, &redirect_callout, NULL, &RedirectCalloutID);
    EXIT_ON_ERROR_CUSTOM(success != FWP_E_ALREADY_EXISTS && success != ERROR_SUCCESS, "FwpmCalloutAdd Redirect");
    success = FwpmCalloutAdd(handle, &stream_callout, NULL, &StreamCalloutID);
    EXIT_ON_ERROR_CUSTOM(success != FWP_E_ALREADY_EXISTS && success != ERROR_SUCCESS, "FwpmCalloutAdd Stream");

    RtlZeroMemory(&redirectFilterv4, sizeof(FWPM_FILTER));
    RtlZeroMemory(&streamDatav4, sizeof(FWPM_FILTER));
    success = FwpmFilterGetByKey(handle, &LAYER_REDIRECT_V4_KEY, &lookup_filter);

    // Filter does not exist
    if (success == FWP_E_FILTER_NOT_FOUND) {
        redirectFilterv4.filterKey = LAYER_REDIRECT_V4_KEY;
        redirectFilterv4.layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
        redirectFilterv4.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
        redirectFilterv4.action.calloutKey = REDIRECT_CALLOUT_KEY;
        redirectFilterv4.weight.type = FWP_EMPTY;
        redirectFilterv4.numFilterConditions = 0;
        redirectFilterv4.displayData.name = v4filtername;
        EXIT_ON_ERROR(FwpmFilterAdd(handle, &redirectFilterv4, NULL, NULL), success, "FilterAdd V4");
    }
    else if (success != ERROR_SUCCESS) { // Error at the method
        std::cout << "Failed Operation detected at FwpmFilterGetByKey Error Code: " << success << "\n";
        goto cleanup;
    } 
    else
        FwpmFreeMemory((void**)&lookup_filter);


    std::cout << " S8 \n";

    success = FwpmFilterGetByKey(handle, &LAYER_STREAM_V4_KEY, &stream_filter_lookup);

    // Filter does not exist
    if (success == FWP_E_FILTER_NOT_FOUND) {
        streamDatav4.filterKey = LAYER_STREAM_V4_KEY;
        streamDatav4.layerKey = FWPM_LAYER_STREAM_V4;
        streamDatav4.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
        streamDatav4.action.calloutKey = STREAM_CALLOUT_KEY;
        streamDatav4.weight.type = FWP_EMPTY;
        streamDatav4.numFilterConditions = 0;
        streamDatav4.displayData.name = streamcallout;
        EXIT_ON_ERROR(FwpmFilterAdd(handle, &streamDatav4, NULL, NULL), success, "FilterAdd streamDatav4");
    }
    else if (success != ERROR_SUCCESS) { // Error at the method
        std::cout << "Failed Operation detected at FwpmFilterGetByKey streamDatav4 Error Code: " << success << "\n";
        goto cleanup;
    } 
    else
        FwpmFreeMemory((void**)&stream_filter_lookup);

    std::cout << " S9 \n";
    EXIT_ON_ERROR(FwpmTransactionCommit(handle), success, "TransactionCommit");

    return ERROR_SUCCESS;

cleanup:
    CloseWFP();
    return -1;
}

void CloseWFP() {
    FwpmCalloutDeleteByKey(handle, &REDIRECT_CALLOUT_KEY);
    FwpmCalloutDeleteByKey(handle, &STREAM_CALLOUT_KEY);
    FwpmTransactionAbort(handle);
    FwpmEngineClose(handle);
}