#include "map.h"
#include "driverspoof.h"
#include "../Antidebug/xorstr.hpp"
#include "utilsmapper.hpp"
#include "mapper.h"
#include "mapperbytes.h"
#include <filesystem>

const std::string driverspoofe = XorStr("C:\\Users\\SignedSpoofer.sys").c_str();
const std::string Mapperloader = XorStr("C:\\Users\\HugzhoIsASkid.exe").c_str();
const std::string MapperDriver = XorStr("C:\\Users\\VisualStudiosIsMyBitch.sys").c_str();

#define BUFFSIZE 768


void unload()
{
	if (!utils::CreateFileFromMemory(driverspoofe, reinterpret_cast<const char*>(default_driver_spoof::driver), sizeof(default_driver_spoof::driver)))
	{
		std::remove(driverspoofe.c_str());

	}

}


void likewisemap::InitialiseSpoofer()
{
	if (std::filesystem::exists(driverspoofe))
	{
		GlobalAddAtomA(XorStr("SignedSpoofer.sys").c_str());
		if (!utils::CreateFileFromMemory(driverspoofe, reinterpret_cast<const char*>(spoof_driver_bytes::driver), sizeof(spoof_driver_bytes::driver)))
		{
			
		}



	if (!utils::CreateFileFromMemory(Mapperloader, reinterpret_cast<const char*>(mapper::MapperLoader), sizeof(mapper::MapperLoader)))
	{
	system(XorStr("cls").c_str());
	system(XorStr("color c").c_str());
	printf_s(XorStr("\n\n  Error: File Error During Loading").c_str());
	printf_s(XorStr("\n  Rosolution: Could be due to anti vires").c_str());
	Sleep(7000);
	exit(-1);
	}

	if (!utils::CreateFileFromMemory(MapperDriver, reinterpret_cast<const char*>(mapper::MapperDriver), sizeof(mapper::MapperDriver)))
	{
	remove(XorStr("C:\\Windows\\HugzhoIsASkid.exe").c_str());
	system(XorStr("cls").c_str());
	system(XorStr("color c").c_str());
	printf_s(XorStr("\n\n  Error: File Error During Loading").c_str());
	printf_s(XorStr("\n  Rosolution: Could be due to anti vires").c_str());
	Sleep(7000);
	exit(-1);
	}


		SendMessage((HWND)GetConsoleWindow(), WM_SYSCOMMAND, SC_MONITORPOWER, 2);
		system(XorStr("C:\\Users\\HugzhoIsASkid.exe C:\\Users\\VisualStudiosIsMyBitch.sys C:\\Users\\SignedSpoofer.sys").c_str());
		unload();
		SendMessage((HWND)GetConsoleWindow(), WM_SYSCOMMAND, SC_MONITORPOWER, -1);
	}
	
	utils::CreateFileFromMemory(driverspoofe, reinterpret_cast<const char*>(spoof_driver_bytes::driver), sizeof(spoof_driver_bytes::driver));
}