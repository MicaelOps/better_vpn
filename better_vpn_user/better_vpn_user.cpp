// better_vpn_user.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "wfp_user_handler.h"

#pragma comment(lib, "Ws2_32.lib")
#define EXIT_ON_ERROR(x, status, topic) \
    if((status=x) != 0) { \
        std::cout << "Failed Operation detected at " << topic << ". Error Code: " << status << "\n"; \
        goto cleanup; \
    }
#define EXIT_ON_ERROR_LAST(x, topic) \
    if(x != 0) { \
        std::cout << "Failed Operation detected at " << topic << ". Error Code: " << GetLastError() << "\n"; \
        goto cleanup; \
    }

#define IOCTL_VPS_SERVER_ADDRESS_CHANGE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_VPS_TOGGLE_REDIRECT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_VPS_TOGGLE_ENCRYPTION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)



typedef struct IO_BUFFER {
    DWORD size;
    LPVOID buffer;
}* PIO_BUFFER;

// Send the initial proxy server's sockaddr to the callout driver for redirection.
int SendInitialProxyServerInfo(LPSTR hostname, LPSTR port, HANDLE handle);

// Acquire the SOCKTADDR structure from the Proxy Server IP's address to convert it to SOCKADDR_STORAGE for the callout driver
int GetProxySockAddr(LPSTR hostname, LPSTR port, OUT addrinfo*& addr);

bool SendIOCTLMessage(ULONG code, HANDLE devicehandle, PIO_BUFFER in, PIO_BUFFER out);
bool SendIOCTLMessage(ULONG code, HANDLE devicehandle);

int main(int argc, char* argv[])
{

    if (argc < 3) {
        std::cout << "Unable to start VPN. Please input the <hostname> and <port> arguments";
        return -1;
    }

    std::cout << "Loading VPN service... \n";
    int cleanuplevel = 0;

    // First checking if the kernel is loaded by using the Service Manager.

    SC_HANDLE schandle = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);

    if (schandle == NULL) {
        std::cout << "Unable to open SC Manager. Error Code: " << GetLastError() << "\n";
        return -1;
    }

    SC_HANDLE vpn_service_handle = OpenService(schandle,
        L"BetterVPN",
        SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_PAUSE_CONTINUE);


    
    if (vpn_service_handle == NULL) {

        DWORD errorCode = GetLastError();

        if (errorCode == ERROR_SERVICE_DOES_NOT_EXIST) {

            std::cout << "Creating Service... \n";

            WCHAR path[300];
            GetFullPathNameW(L"better_vpn.sys", 300, path, nullptr);

            std::wcout << path << "\n";

            // Installing Service
            vpn_service_handle = CreateService(
                schandle,
                L"BetterVPN",
                L"Better VPN Service",
                SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT | SERVICE_QUERY_STATUS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                path,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL);

            // The installation of the service failed.
            if (vpn_service_handle == NULL) {
                CloseServiceHandle(schandle);
                std::cout << "Unable to install Service Error Code:" << GetLastError() << "\n";
                return -1;
            }
        }

        else { // error is not due to service not being nonexistent

            std::cout << "Unable to OpenService. Error Code:" << errorCode << "\n";
            CloseServiceHandle(schandle);
            return -1;
        }
        
    }
    else { // OpenService succeded getting the handle.

        SERVICE_STATUS serviceStatus;
        if (!QueryServiceStatus(vpn_service_handle, &serviceStatus)) {
            std::cout << "Unable to query VPN Service status. Error Code:" << GetLastError() << "\n";
            CloseServiceHandle(vpn_service_handle);
            CloseServiceHandle(schandle);
            return -1;
        }

        if (serviceStatus.dwCurrentState == SERVICE_STOPPED ||
            serviceStatus.dwCurrentState == SERVICE_STOP_PENDING) {

            std::cout << "Starting Service...\n";
            if (serviceStatus.dwCurrentState == SERVICE_STOP_PENDING) {
                Sleep(3000);  // Wait for it to fully stop
            }

            if (!StartService(vpn_service_handle, 0, nullptr)) {
                std::cout << "Unable to start service. Error Code: " << GetLastError() << "\n";
                CloseServiceHandle(vpn_service_handle);
                CloseServiceHandle(schandle);
                return -1;
            }
        }
        else if (serviceStatus.dwCurrentState == SERVICE_PAUSED ||
            serviceStatus.dwCurrentState == SERVICE_PAUSE_PENDING) {

            std::cout << "Resuming Service...\n";
            if (serviceStatus.dwCurrentState == SERVICE_PAUSE_PENDING) {
                Sleep(3000);
            }

            if (!ControlService(vpn_service_handle, SERVICE_CONTROL_CONTINUE, &serviceStatus)) {
                std::cout << "Unable to resume service. Error Code: " << GetLastError() << "\n";
                CloseServiceHandle(vpn_service_handle);
                CloseServiceHandle(schandle);
                return -1;
            }
        }
        else if (serviceStatus.dwCurrentState == SERVICE_RUNNING ||
            serviceStatus.dwCurrentState == SERVICE_START_PENDING) {
            std::cout << "Service already running.\n";
        }
        else {

            std::cout << "Unknown state: " << serviceStatus.dwCurrentState << "\n";
            CloseServiceHandle(vpn_service_handle);
            CloseServiceHandle(schandle);
            return -1;
        }
    }

    std::cout << "Handle obtained.. Attempting communcication... \n";
    HANDLE deviceHandle = CreateFile(
        L"\\\\.\\BetterVPN",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);


    if (deviceHandle == INVALID_HANDLE_VALUE) {
        std::cout << "Unable to communicate with VPN Driver. Error Code: " << GetLastError() << "\n";

        SERVICE_STATUS serviceStatus;

        bool success = ControlService(vpn_service_handle, SERVICE_CONTROL_STOP, &serviceStatus);

        if (success && serviceStatus.dwCurrentState == SERVICE_STOP_PENDING) 
            Sleep(3000);  // Wait for it to fully stop
        

        CloseServiceHandle(vpn_service_handle);
        CloseServiceHandle(schandle);
        return -1;
    }

    std::string command;
    ULONG code = 0;
    WSADATA wsaData;
    int result;

    EXIT_ON_ERROR(SetupWFP(), result, "SetupWFP");
    
    EXIT_ON_ERROR(WSAStartup(MAKEWORD(2, 2), &wsaData), result, "WSAStartup"); // Just used for obtaining the proxy server's sockaddr

    EXIT_ON_ERROR_LAST(SendInitialProxyServerInfo(argv[1], argv[2], deviceHandle), "SendInitialProxyServerInfo");

    std::cout << "You can start typing the commands (toggle_encryption, toggle_vpn, vpn_server_change, stop) \n";

    do {
        
        std::cin >> command;
        
        if (command == "toggle_encryption") 
            code = IOCTL_VPS_TOGGLE_ENCRYPTION;

        else if (command == "toggle_vpn") 
            code = IOCTL_VPS_TOGGLE_REDIRECT; 

        else if (command == "vpn_server_change") 
            code = IOCTL_VPS_SERVER_ADDRESS_CHANGE;

        
        if (code == 0) 
            continue;
        

        bool success = SendIOCTLMessage(code, deviceHandle);

        code = 0;

        if (!success)
            std::cout << "Failed to send command! Error Code: " << GetLastError() << "\n";
        else
            std::cout << "Command messaged successfully.";


    } while (command != "stop");

cleanup:

    WSACleanup();

    std::cout << "Closing VPN Filters... \n";
    CloseWFP();

    std::cout << "Closing VPN File Handle... \n";
    CloseHandle(deviceHandle);

    // Closing the VPN Service before closing the handles
    SERVICE_STATUS serviceStatus;
    ControlService(vpn_service_handle, SERVICE_CONTROL_STOP, &serviceStatus);

    std::cout << "Closing VPN Service Handle... \n";
    CloseServiceHandle(vpn_service_handle);

    std::cout << "Closing Service Manager Handle... \n";
    CloseServiceHandle(schandle);

    return 0;
}

bool SendIOCTLMessage(ULONG code, HANDLE devicehandle, PIO_BUFFER in, PIO_BUFFER out) {
    DWORD bytesReturned = 0;
    DeviceIoControl(devicehandle, code, in->buffer, in->size, out->buffer, out->size, &bytesReturned, nullptr);
    return DeviceIoControl(devicehandle, code, in->buffer, in->size, out->buffer, out->size, &bytesReturned, nullptr);
}
bool SendIOCTLMessage(ULONG code, HANDLE devicehandle) {
    IO_BUFFER in{0, nullptr}, out{ 0, nullptr };
    return SendIOCTLMessage(code, devicehandle, &in, &out);
}

int GetProxySockAddr(LPSTR hostname, LPSTR port, OUT addrinfo*& addr) {

    addrinfo* result = NULL;
    addrinfo hints;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int addrresult = getaddrinfo(hostname, port, &hints, &result);

    if (addrresult != 0) {
        std::cout << "Failed to getaddrinfo() Error Code:" << addrresult << "\n";
        return -1;
    }
    addr = result;
    return ERROR_SUCCESS;
}
// Send the initial proxy server's sockaddr to the callout driver for redirection.
int SendInitialProxyServerInfo(LPSTR hostname, LPSTR port, HANDLE handle) {

    addrinfo* proxyaddrinfo;
    
    if (GetProxySockAddr(hostname, port, proxyaddrinfo) != ERROR_SUCCESS) {
        std::cout << "Unable to get socket address.";
        return -1;
    }

    IO_BUFFER inData ={ sizeof(proxyaddrinfo->ai_addr), &proxyaddrinfo->ai_addr };
    IO_BUFFER outData ={ 0, nullptr };

    if (!SendIOCTLMessage(IOCTL_VPS_SERVER_ADDRESS_CHANGE, handle, &inData, &outData)) {
        std::cout << "Unable to send message to the driver Error: " << GetLastError();
        return -1;
    }

    freeaddrinfo(proxyaddrinfo);
    return ERROR_SUCCESS;
}
