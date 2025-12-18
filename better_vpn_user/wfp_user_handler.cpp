
#include "wfp_user_handler.h"
#include <iostream>

#define EXIT_ON_ERROR(x, status, topic) \
    if((status=x) != ERROR_SUCCESS) { \
        std::cout << "Failed Operation detected at " << topic << ". Error Code: " << status << "\n"; \
        goto cleanup; \
    }

DEFINE_GUID(
    FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
    0xc6e63c8c,
    0xb784,
    0x4562,
    0xaa, 0x7d, 0x0a, 0x67, 0xcf, 0xca, 0xf9, 0xa3
);
DEFINE_GUID(
    FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
    0x587e54a8,
    0x22c4,
    0x4527,
    0x9d, 0x9c, 0x54, 0xcb, 0x36, 0x1f, 0x7e, 0x7e
);
DEFINE_GUID(
    PROVIDER_KEY,
    0x3437e444,
    0xacf5,
    0x4bdf,
    0x96, 0xa7, 0x31, 0x83, 0x08, 0x38, 0x29, 0xee
);

static HANDLE handle = nullptr;




DWORD SetupWFP() {

    DWORD success = ERROR_SUCCESS;
    
    // one filter is responsible for redirecting IPv4 IPv6 connections to the VPN Server
    // Other filter is responsible for getting the clone the packet data and inject a new packet with encrypted data to the stream
    FWPM_FILTER redirectFilterv4, redirectFilterv6, packetdataFilter;

    EXIT_ON_ERROR(FwpmEngineOpen(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &handle), success, "EngineOpen");
    EXIT_ON_ERROR(FwpmTransactionBegin(handle, 0), success, "TransactionBegin");

    RtlZeroMemory(&redirectFilterv4, sizeof(FWPM_FILTER));
    RtlZeroMemory(&redirectFilterv6, sizeof(FWPM_FILTER));
    RtlZeroMemory(&packetdataFilter, sizeof(FWPM_FILTER));

    redirectFilterv4.layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
    redirectFilterv4.action.type = FWP_ACTION_PERMIT;
    redirectFilterv4.weight.type = FWP_EMPTY;
    redirectFilterv4.numFilterConditions = 0;
    EXIT_ON_ERROR(FwpmFilterAdd(handle, &redirectFilterv4, NULL, NULL), success, "FilterAdd V4");

    redirectFilterv6.layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V6;
    redirectFilterv6.action.type = FWP_ACTION_PERMIT;
    redirectFilterv6.weight.type = FWP_EMPTY;
    redirectFilterv6.numFilterConditions = 0;

    EXIT_ON_ERROR(FwpmFilterAdd(handle, &redirectFilterv6, NULL, NULL), success, "FilterAdd V6");
    EXIT_ON_ERROR(FwpmTransactionCommit(handle), success, "TransactionCommit");

cleanup:
    if (success != ERROR_SUCCESS) {
        FwpmTransactionAbort(handle);
        FwpmEngineClose(handle);
        
        return false;
    }
    return true;
}

void CloseWFP() {
    FwpmEngineClose(handle);
}