#pragma once


#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN  // Excludes rarely-used Windows headers
#endif

#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_         // Prevents windows.h from including winsock.h (old version)
#endif

#include <winsock2.h>   
#include <ws2tcpip.h>

#include <Windows.h>
#include <winioctl.h>
#include <fwpmu.h>        

#pragma comment(lib, "Ws2_32.lib") 
#pragma comment(lib, "fwpuclnt.lib") 
#pragma comment(lib, "advapi32.lib")

void CloseWFP();
DWORD SetupWFP();