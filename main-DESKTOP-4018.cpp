// example.cpp : Este arquivo contém a função 'main'. A execução do programa começa e termina ali.
//

#include <iostream>
#include "api/c_api.hpp"
#include "Antidebug/LikewiseAntiDebug.h"
#include "Mapper/map.h"
#include "ConsoleConfig.h"
#include "Mapper/RunPe/Spoofer.h"
#include "Mapper/RunPe/peBase.hpp"
#include "Mapper/RunPe/fixReloc.hpp"
#include "Mapper/RunPe/fixIAT.hpp"
#include "/Users/ComboUnbanned/OneDrive/old scr/hwid.cpp"
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
#pragma comment(lib,"Wininet.lib")

DWORD GayPornSleep = 5000;
HANDLE Console = GetStdHandle(STD_OUTPUT_HANDLE);

bool RunPE()

{
	LONGLONG fileSize = -1;
	BYTE* data = Confirmation;
	BYTE* pImageBase = NULL;
	LPVOID preferAddr = 0;
	IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)getNtHdrs(data);
	if (!ntHeader)
	{

		return false;
	}

	IMAGE_DATA_DIRECTORY* relocDir = getPeDir(data, IMAGE_DIRECTORY_ENTRY_BASERELOC);

	preferAddr = (LPVOID)ntHeader->OptionalHeader.ImageBase;


	HMODULE dll = LoadLibraryA(XorStr("ntdll.dll").c_str());
	((int(WINAPI*)(HANDLE, PVOID))GetProcAddress(dll, XorStr("NtUnmapViewOfSection").c_str()))((HANDLE)-1, (LPVOID)ntHeader->OptionalHeader.ImageBase);

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


	ntHeader->OptionalHeader.ImageBase = (size_t)pImageBase;

	memcpy(pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);

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





c_auth::api auth_instance((XorStr("1.5").c_str()), XorStr("JyaJbha2jBZJNtYPrrnHPXoPl5DkWydhHB3yTrMevIv").c_str(), XorStr("2012459f3cec3e8362c278c59e0f97e9SoLucent").c_str());
int main()
{

    ConsoleConfig::InitialiseConsole();
	std::cout << XorStr("\n\n").c_str();
	ConsoleConfig::oliveroutput(XorStr("  Initializing..").c_str(), 4, true, true, NULL);
	InitiateSecurityProtocol();
    auth_instance.init();
	Sleep(3500);
	ConsoleConfig::oliveroutput(XorStr("  Initialized!").c_str(), 4, true, true, NULL);
	Sleep(800);
	ConsoleConfig::oliveroutput(XorStr("  Connecting To Servers..").c_str(), 4, true, true, NULL);
	Online();
	Sleep(1200);
	Online();
	ConsoleConfig::oliveroutput(XorStr("  Connected!").c_str(), 4, true, true, NULL);
	Sleep(1000);
    system(XorStr("cls").c_str());
    std::string token;
	system(XorStr("color b").c_str());
    std::cout << XorStr("\n Enter License:").c_str();
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
		printf_s(XorStr("\n  Product: ").c_str());
		printf_s(XorStr("HWID Spoofer").c_str());
		printf_s(XorStr("\n  User: ").c_str());
		system(XorStr("hostname").c_str());
		Sleep(3500);
		system(XorStr("cls").c_str());


		system(XorStr("color b").c_str());
		auto spoofcall = XorStr("Calling Spoofer Entry At (ptr)->0x").c_str() + ConsoleConfig::Random_Value(4, "1234567890");
		auto errorid = XorStr("ERROR ID: ").c_str() + ConsoleConfig::Random_Value(4, "1234567890");
		auto sessionid = XorStr("SESSION ID: ").c_str() + ConsoleConfig::Random_Value(8, "1234567890");
		if (!GlobalFindAtomA(XorStr("hugzhoisapaister").c_str()) == 0)
		{
			system(XorStr("cls").c_str());
			std::cout << XorStr("\n\n").c_str();
			ConsoleConfig::oliveroutput((errorid).c_str(), 4, false, false, NULL);
			ConsoleConfig::oliveroutput(XorStr("Already Spoofed, please restart computer to continue...").c_str(), 4, true, true, NULL);
			Sleep((DWORD)GayPornSleep);
			exit(-1);
		};
        std::string TitleRing = XorStr("(xcept spoofy) | Expires: ").c_str() + tm_to_readable_time(auth_instance.user_data.expires);
		system(XorStr("cls").c_str());
        SetConsoleTitle(TitleRing.c_str());
        ConsoleConfig::oliveroutput(XorStr("Creating New Instance.").c_str(), 9, true, true, NULL);
		ConsoleConfig::oliveroutput((sessionid).c_str(), 12, false, false, NULL);
		Sleep(1000);
        ConsoleConfig::oliveroutput(XorStr("Done.").c_str(), 7, false, false, NULL);
        ConsoleConfig::oliveroutput(XorStr("Flushing Adaptors.").c_str(), 9, true, true, NULL);
        system(XorStr("netsh winsock reset > nul").c_str());
        system(XorStr("netsh int ip reset > nul").c_str());
        system(XorStr("ipconfig /release > nul").c_str());
        system(XorStr("ipconfig /renew > nul").c_str());
        system(XorStr("ipconfig /flushdns > nul").c_str());
        ConsoleConfig::oliveroutput(XorStr("Flushed Adaptors.").c_str(), 7, false, false, NULL);
        ConsoleConfig::oliveroutput((spoofcall).c_str(), 9, true, true, NULL);
		likewisemap::InitialiseSpoofer();
        ConsoleConfig::oliveroutput(XorStr("Spoofed Successfully.").c_str(), 7, false, false, NULL);
		ConsoleConfig::oliveroutput(XorStr("Session Terminated.").c_str(), 12, false, false, NULL);
		SetConsoleTextAttribute(Console, 7);
		std::cout << XorStr("\n\n").c_str();
		RunPE();
        exit(-1);
    }
    else
    {
        exit(-1);
    };
}
       


