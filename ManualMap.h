#pragma once
#include "Utils.h"

class ManualMap
{
public:
	ManualMap(PVOID Buffer, DWORD FileSize, HANDLE hProcess, DWORD Pid);
	~ManualMap();
	bool MapDll();

private:
	PVOID Buffer;
	DWORD Size;
	HANDLE hProcess;
	DWORD PID;
};

