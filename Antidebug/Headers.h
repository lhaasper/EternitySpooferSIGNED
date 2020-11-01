#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include "ThreadManager.h"
#include "xorstr.hpp"
#include <filesystem>
#include <TlHelp32.h>
#ifndef PCH_H
#define PCH_H
#include <string>
#include <vector>
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <IPTypes.h>
#include <Iphlpapi.h>
#include <icmpapi.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <ShlObj.h>
#include <stdarg.h>
#include <strsafe.h>
#include <tchar.h>
#include <time.h>
#include <TlHelp32.h>
#include <Wbemidl.h>
#include <devguid.h>    // Device guids
#include <winioctl.h>	// IOCTL
#include <intrin.h>		// cpuid()
#include <locale.h>		// 64-bit wchar atoi
#include <powrprof.h>	// check_power_modes()
#include <SetupAPI.h>
#include <algorithm>
#include <cctype>
#include <slpublic.h> // SLIsGenuineLocal
#include <random>
#include <assert.h>
#include "../Mapper/map.h"
#include <random>
#include <filesystem>
#include <TlHelp32.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Mpr.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Winmm.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "powrprof.lib")
#pragma comment(lib, "Slwga.lib")


#define BUFFSIZE 768


 #include "API/Common.h"
#include "API/VersionHelpers.h"
#include "API/log.h"
#include "API/Utils.h"
#include "API/WinStructs.h"
#include "API/ApiTypeDefs.h"
#include "API/APIs.h"
#include "API/winapifamily.h"

#include "../AntiDebug/LikewiseAntiDebug.h"


#include "AntiDebugging/CheckRemoteDebuggerPresent.h"
#include "AntiDebugging/IsDebuggerPresent.h"
#include "AntiDebugging/BeingDebugged.h"
#include "AntiDebugging/ProcessHeap_Flags.h"
#include "AntiDebugging/ProcessHeap_ForceFlags.h"
#include "AntiDebugging/NtGlobalFlag.h"
#include "AntiDebugging/CloseHandle_InvalidHandle.h"
#include "AntiDebugging/OutputDebugStringAPI.h"
#include "AntiDebugging/HardwareBreakpoints.h"
#include "AntiDebugging/SoftwareBreakpoints.h"
#include "AntiDebugging/TrapFlag.h"
#include "AntiDebugging/MemoryBreakpoints_PageGuard.h"
#include "AntiDebugging/SeDebugPrivilege.h"
#include "AntiDebugging/SetHandleInformation_API.h"
#include "AntiDebugging/TLS_callbacks.h"
#include "AntiDebugging/ModuleBoundsHookCheck.h"
#include "AntiDebugging/WUDF_IsDebuggerPresent.h" 


/* Anti dumping headers */
#include "Antidumping/ErasePEHeaderFromMemory.h"
#include "Antidumping/SizeOfImage.h"


/* Delay Execution */
#include "TimingAttacks/timing.h"





#endif //PCH_H
