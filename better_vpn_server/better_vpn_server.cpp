

#include <iostream>


#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN  // Excludes rarely-used Windows headers
#endif

#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_         // Prevents windows.h from including winsock.h (old version)
#endif

#include <winsock2.h>   
#include <ws2tcpip.h>
#include "concurrent_unordered_set.h" // Copied from my minecraft server project

#define EXIT_ON_ERROR(code, status, topic)  \
    if((status=code) != 0) { \
        std::cout << "Error on " << topic << " Error: " << status << " \n"; \
        goto cleanup; \
    }


#define WSAEXIT_ON_ERROR(code, status, topic)  \
    if((status=code) == 0) { \
        std::cout << "Error on " << topic << " Error: " << WSAGetLastError() << " \n"; \
        goto cleanup; \
    }


SOCKET listenSocket;
HANDLE listenPort;
LPFN_ACCEPTEX lpfnAcceptEx = nullptr;

concurrent_unordered_set<SOCKET> connections;


// Max Connections on the VPN Server
constexpr unsigned short maxConnections = 20;

bool startupServer();
void closeServer();

int main()
{

    std::string command;

    if (!startupServer()) 
        return -1;
    
    do {
        std::cin >> command;
        
       // if i ever want to implement some metrics in the future.
    } while (command != "stop");

    std::cout << "Shutting down... ";
    closeServer();
    return -1;
}


bool startupServer() {
    WSADATA wsadata;
    DWORD errorCode;
    GUID guidAcceptEx = WSAID_ACCEPTEX;
    addrinfo hints{}, * result = nullptr;

    EXIT_ON_ERROR(WSAStartup(MAKEWORD(2, 2), &wsadata), errorCode, "WSAStartup");

    // Making sure we dont collect garbage values
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    EXIT_ON_ERROR(getaddrinfo(NULL, "3150", &hints, &result), errorCode, "getaddrinfo");


    WSAEXIT_ON_ERROR(WSASocket(result->ai_family, result->ai_socktype, result->ai_protocol, nullptr, 0, WSA_FLAG_OVERLAPPED), listenSocket, "WSASocket");

    WSAEXIT_ON_ERROR(CreateIoCompletionPort((HANDLE)listenSocket, nullptr, 0, 0), listenPort, "CreateIoCompletionPort");
    freeaddrinfo(result);

    EXIT_ON_ERROR(bind(listenSocket, (SOCKADDR*)&result->ai_addr, sizeof(result->ai_addr)), errorCode, "bind");
    EXIT_ON_ERROR(listen(listenSocket, 300), errorCode, "listen");

    DWORD bytesReturned;

    EXIT_ON_ERROR(WSAIoctl(listenSocket,
        SIO_GET_EXTENSION_FUNCTION_POINTER,
        &guidAcceptEx,
        sizeof(guidAcceptEx),
        &lpfnAcceptEx,
        sizeof(lpfnAcceptEx),
        &bytesReturned,
        nullptr,
        nullptr),
        errorCode, "WSAIoctl");



cleanup:
    return false;
}
void closeServer() {
    CancelIoEx((HANDLE)listenSocket, nullptr);
    closesocket(listenSocket);
    std::cout << "Shutting down... ";
}