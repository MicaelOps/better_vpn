#include "wfp_user_handler.h"
#include <Windows.h>
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
    PROVIDER_KEY,
    0x3437e444,
    0xacf5,
    0x4bdf,
    0x96, 0xa7, 0x31, 0x83, 0x08, 0x38 0x29, 0xee
);

bool SetupWFP(HANDLE& handle) {

    DWORD success = ERROR_SUCCESS;
    
    // One filter is responsible for redirecting connect() responses to the VPN Server
    // Other filter is responsible for getting the clone the packet data and inject a new packet with encrypted data to the stream
    FWPM_FILTER redirectFilter, packetdataFilter;

    EXIT_ON_ERROR(FwpmEngineOpen(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &handle), success, "EngineOpen");
    EXIT_ON_ERROR(FwpmTransactionBegin(handle, 0), success, "TransactionBegin");

    RtlZeroMemory(&redirectFilter, sizeof(FWPM_FILTER));
    RtlZeroMemory(&packetdataFilter, sizeof(packetdataFilter));

    redirectFilter.layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
    redirectFilter.action.type = FWP_ACTION_PERMIT;
    redirectFilter.weight.type = FWP_EMPTY;
    redirectFilter.numFilterConditions = 0;
    EXIT_ON_ERROR(FwpmFilterAdd(handle, &redirectFilter, NULL, NULL), success, "FilterAdd");

    EXIT_ON_ERROR(FwpmTransactionCommit(handle), success, "TransactionCommit");
cleanup:
    FwpmEngineClose(handle);
    return success == ERROR_SUCCESS;
}

void CloseWFP(HANDLE handle) {
    FwpmEngineClose(handle);
}