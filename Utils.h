#pragma once
#include <Windows.h>
#include <stdio.h>
#include <psapi.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <iostream>
#include <vector>

#pragma comment(lib,"ntdll")
#pragma comment(lib,"psapi")

static bool GetProcessToken()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tp;

	if (!::OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return false;

	if (!::LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
	{
		::CloseHandle(hToken);
		return false;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), NULL, NULL))
	{
		::CloseHandle(hToken);
		return false;
	}

	::CloseHandle(hToken);
	return true;
}

static BOOL GetRemoteModuleHandle(unsigned long pId, const char* module, HMODULE* mod)
{
	BOOL fReturn = false;
	MODULEENTRY32 modEntry;
	HANDLE tlh = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pId);

	modEntry.dwSize = sizeof(MODULEENTRY32);
	Module32First(tlh, &modEntry);

	do
	{
		if (strstr(modEntry.szModule, module) || lstrcmpiA(modEntry.szModule, module))
		{
			*mod = modEntry.hModule;
			fReturn = true;
			break;
		}

		modEntry.dwSize = sizeof(MODULEENTRY32);

	} while (Module32Next(tlh, &modEntry));

	CloseHandle(tlh);
	return fReturn;
}

static DWORD GetProcessid(const std::string ProcessName)
{
	DWORD pID = 0;

	PROCESSENTRY32   pe32;
	HANDLE         hSnapshot = NULL;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(hSnapshot, &pe32) == TRUE)
	{
		while (Process32Next(hSnapshot, &pe32) == TRUE)
		{
			if (strcmp(pe32.szExeFile, ProcessName.c_str()) == 0)
			{
				CloseHandle(hSnapshot);
				return pe32.th32ProcessID;
			}
		}
	}
	return 0;
}

static bool CheckIfExists(DWORD dwPid)
{
	HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, dwPid);
	DWORD dwReturn = WaitForSingleObject(hProcess, 0);
	if (hProcess)
		CloseHandle(hProcess);
	return dwReturn == WAIT_TIMEOUT;
};

static std::string GetCurrentPatch() {
	char buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	std::string::size_type pos = std::string(buffer).find_last_of("\\/");
	return  std::string(buffer).substr(0, pos);
}

static const std::size_t GetFunctionSize(const void* function)
{
	if (function == std::nullptr_t())
		return 0u;

	std::size_t size = 0u;
	bool break_point_found = false;

	const BYTE* bytes = static_cast<const BYTE*>(function);
	constexpr BYTE ret = 0xC3;
	constexpr BYTE break_point = 0xCC;

	bool skipped = false;

	while (true)
	{
		if (size && bytes[size] == break_point && bytes[size - 1] == ret)
			break_point_found = true;

		if (break_point_found && bytes[size] != break_point)
			break;

		size++;
	};

	return size;
};

static bool CheckThemida(HANDLE hProcess, MODULEINFO Info)
{
	SIZE_T Size = 0;
	BYTE bByte = 0;

	if (ReadProcessMemory(hProcess, Info.lpBaseOfDll, &bByte, 1, &Size) && bByte == 0x4D)
		return true;

	return false;
};

static MODULEINFO GetProcessBase(HANDLE hProcess)
{
	_MEMORY_BASIC_INFORMATION mbi;
	ULONG_PTR uCurrent = 0;
	MODULEINFO mod;
	BYTE PE[0x1000];
	ZeroMemory(&mbi, sizeof(mbi));
	ZeroMemory(&mod, sizeof(mod));
	do
	{
		ZeroMemory(&PE, 0x1000);
		if (uCurrent > 0 && ReadProcessMemory(hProcess, reinterpret_cast<PVOID>(uCurrent), &PE, 0x1000, 0) &&
			uCurrent != 0 && mbi.Type == MEM_IMAGE && mbi.Protect != PAGE_NOACCESS && mbi.Protect != 0 && PE[0] == 0x4D && PE[1] == 0x5A)
		{
			IMAGE_NT_HEADERS* ProcessHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<DWORD_PTR>(PE) + PIMAGE_DOS_HEADER(reinterpret_cast<DWORD_PTR>(PE))->e_lfanew);
			mod.EntryPoint = reinterpret_cast<PVOID>(ProcessHeader->OptionalHeader.AddressOfEntryPoint);
			mod.lpBaseOfDll = reinterpret_cast<PVOID>(uCurrent);
			mod.SizeOfImage = ProcessHeader->OptionalHeader.SizeOfImage;
			break;
		}
		uCurrent += mbi.RegionSize;
	} while (VirtualQueryEx(hProcess, reinterpret_cast<PVOID>(uCurrent), &mbi, sizeof(mbi)));
	return mod;
};