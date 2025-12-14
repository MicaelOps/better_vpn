#pragma once
#include <fwpmu.h>

#pragma comment (lib, "fwpuclnt.lib")
#pragma comment (lib, "advapi32.lib")

void CloseWFP();
bool SetupWFP();