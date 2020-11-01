#include "ManualMap.h"

using LPFN_MESSAGEBOXA = HMODULE(APIENTRY*)(HWND, LPCSTR, LPCSTR, UINT);
using LPFN_LOADLIBRARY = HMODULE(APIENTRY*)(LPCSTR);
using LPFN_GETMODULEHANDLE = HMODULE(APIENTRY*)(LPCSTR);
using LPFN_GETPROCADDRESS = FARPROC(APIENTRY*)(HMODULE, LPCSTR);
using LPFN_DLLMAIN = BOOL(WINAPI*)(HMODULE, DWORD, PVOID);

typedef struct _LOADER_PARAMETERS
{
	PVOID pImageBase;
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_BASE_RELOCATION pBaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;
	LPFN_LOADLIBRARY fLoadLibrary;
	LPFN_GETMODULEHANDLE fGetModuleHandle;
	LPFN_GETPROCADDRESS fGetProcAddress;
} LOADER_PARAMETERS, * PLOADER_PARAMETERS;

uintptr_t Execute(void* loaderParameters)
{
	if (loaderParameters == nullptr)
		return 0;

	PLOADER_PARAMETERS pParameters = reinterpret_cast<PLOADER_PARAMETERS>(loaderParameters);

	PIMAGE_BASE_RELOCATION pBaseRelocation = pParameters->pBaseRelocation;

	uintptr_t delta = reinterpret_cast<uintptr_t>((reinterpret_cast<LPBYTE>(pParameters->pImageBase) - pParameters->pNtHeaders->OptionalHeader.ImageBase));

	while (pBaseRelocation->VirtualAddress)
	{
		if (pBaseRelocation->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			uintptr_t count = (pBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* list = reinterpret_cast<WORD*>(pBaseRelocation + 1);

			for (uintptr_t i = 0; i < count; i++)
			{
				if (list[i])
				{
					uintptr_t* pointer = reinterpret_cast<uintptr_t*>(reinterpret_cast<LPBYTE>(pParameters->pImageBase) + (pBaseRelocation->VirtualAddress + (list[i] & 0xFFF)));
					*pointer += delta;
				};
			};
		};

		pBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<LPBYTE>(pBaseRelocation) + pBaseRelocation->SizeOfBlock);
	};

	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = pParameters->pImportDescriptor;

	while (pImportDescriptor->Characteristics)
	{
		PIMAGE_THUNK_DATA originalThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<LPBYTE>(pParameters->pImageBase) + pImportDescriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA firstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<LPBYTE>(pParameters->pImageBase) + pImportDescriptor->FirstThunk);

		HMODULE hModule = pParameters->fGetModuleHandle(reinterpret_cast<LPCSTR>(pParameters->pImageBase) + pImportDescriptor->Name);

		if (!hModule)
			hModule = pParameters->fLoadLibrary(reinterpret_cast<LPCSTR>(pParameters->pImageBase) + pImportDescriptor->Name);

		if (!hModule)
			return 0;

		while (originalThunk->u1.AddressOfData)
		{
			if (originalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				uintptr_t function = reinterpret_cast<uintptr_t>(pParameters->fGetProcAddress(hModule, reinterpret_cast<LPCSTR>(originalThunk->u1.Ordinal & 0xFFFF)));

				if (!function)
					return false;

				firstThunk->u1.Function = function;
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<LPBYTE>(pParameters->pImageBase) + originalThunk->u1.AddressOfData);

				uintptr_t function = reinterpret_cast<uintptr_t>(pParameters->fGetProcAddress(hModule, reinterpret_cast<LPCSTR>(importByName->Name)));

				if (!function)
					return 0;

				firstThunk->u1.Function = function;
			};

			originalThunk++;
			firstThunk++;
		};

		pImportDescriptor++;
	};

	if (pParameters->pNtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		LPFN_DLLMAIN fEntryPoint = reinterpret_cast<LPFN_DLLMAIN>(reinterpret_cast<LPBYTE>(pParameters->pImageBase) + pParameters->pNtHeaders->OptionalHeader.AddressOfEntryPoint);
		return fEntryPoint(reinterpret_cast<HMODULE>(pParameters->pImageBase), DLL_PROCESS_ATTACH, nullptr);
	};

	return 0;
}

ManualMap::ManualMap(PVOID Buffer, DWORD FileSize, HANDLE hProcess, DWORD Pid)
{
	this->Buffer = Buffer;
	this->Size = FileSize;
	this->hProcess = hProcess;
	this->PID = Pid;
}


bool ManualMap::MapDll()
{
	PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(Buffer);

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((reinterpret_cast<LPBYTE>(Buffer) + pDosHeader->e_lfanew));

	if ((sizeof(uintptr_t) == 8 && pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386))
		return false;

	if ((sizeof(uintptr_t) == 4 && pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64))
		return false;

	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return false;

	if (!(pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL))
		return false;

	PVOID Imagen_Base = VirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!Imagen_Base)
		return false;

	if (!WriteProcessMemory(hProcess, Imagen_Base, Buffer, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL))
	{
		printf("\nError: Unable to copy headers to target process (%d)\n", GetLastError());

		VirtualFreeEx(hProcess, Imagen_Base, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	PIMAGE_SECTION_HEADER pSectionHeaders = reinterpret_cast<PIMAGE_SECTION_HEADER>(pNtHeaders + 1);

	for (uintptr_t i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		WriteProcessMemory(hProcess, reinterpret_cast<PVOID>(reinterpret_cast<LPBYTE>(Imagen_Base) + pSectionHeaders[i].VirtualAddress),
			reinterpret_cast<PVOID>(reinterpret_cast<LPBYTE>(Buffer) + pSectionHeaders[i].PointerToRawData), pSectionHeaders[i].SizeOfRawData, NULL);
	}

	size_t loader_code_size = GetFunctionSize(Execute);

	PVOID loader_code = VirtualAllocEx(hProcess, NULL, loader_code_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	LOADER_PARAMETERS parameters;
	memset(&parameters, 0, sizeof(LOADER_PARAMETERS));

	parameters.pImageBase = PVOID(Imagen_Base);
	parameters.pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<LPBYTE>(parameters.pImageBase) + pDosHeader->e_lfanew);
	parameters.pBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<LPBYTE>(parameters.pImageBase) + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	parameters.pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<LPBYTE>(parameters.pImageBase) + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	parameters.pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<LPBYTE>(parameters.pImageBase) + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	parameters.fLoadLibrary = reinterpret_cast<LPFN_LOADLIBRARY>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"));
	parameters.fGetModuleHandle = reinterpret_cast<LPFN_GETMODULEHANDLE>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetModuleHandleA"));
	parameters.fGetProcAddress = reinterpret_cast<LPFN_GETPROCADDRESS>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress"));

	PVOID pParameters = VirtualAllocEx(hProcess, NULL, sizeof(LOADER_PARAMETERS), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!WriteProcessMemory(hProcess, loader_code, &Execute, loader_code_size, NULL))
	{
		VirtualFreeEx(hProcess, Imagen_Base, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, loader_code, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, pParameters, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	if (!WriteProcessMemory(hProcess, pParameters, &parameters, sizeof(LOADER_PARAMETERS), NULL))
	{
		VirtualFreeEx(hProcess, Imagen_Base, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, loader_code, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, pParameters, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}
	DWORD TID;

	HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loader_code), pParameters, 0, &TID);


	CloseHandle(hThread);


	if (pNtHeaders->OptionalHeader.AddressOfEntryPoint)

		return true;
}

ManualMap::~ManualMap()
{
}
