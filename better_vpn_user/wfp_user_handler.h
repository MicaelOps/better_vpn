#pragma once

// CRITICAL ORDER: These defines and includes MUST happen in this exact order
// to prevent winsock redefinition errors in Visual Studio

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN  // Excludes rarely-used Windows headers
#endif

#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_         // Prevents windows.h from including winsock.h (old version)
#endif

// WinSock 2 headers MUST come before Windows.h
#include <winsock2.h>   
#include <ws2tcpip.h>

// Now safe to include Windows.h
#include <Windows.h>

#include <winioctl.h>

// Windows Filtering Platform
#include <fwpmu.h>        

// Link required libraries
#pragma comment(lib, "Ws2_32.lib") 
#pragma comment(lib, "fwpuclnt.lib") 
#pragma comment(lib, "advapi32.lib")

// Function declarations
void CloseWFP();
DWORD SetupWFP();