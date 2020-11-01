#pragma once
//#include "AntiDebug/Headers.h"
#include <wincrypt.h>
#include <ShlObj.h>
#include <iostream>
#include <filesystem>
#include "AntiDebug/ThreadManager.h"
#include "AntiDebug/xorstr.hpp"
#include <random>
#define KRED     "\x1B[31m"     /* Red */
#define GREEN   "\x1B[32m"      /* Green */
#define WHITE   "\x1B[37m"     /* White */
#define BUFFSIZE 768



namespace ConsoleConfig
{
	std::string Random_Value(const int len, std::string b)
	{
		const std::string alpha_numeric(b);

		std::default_random_engine generator{ std::random_device{}() };
		const std::uniform_int_distribution< std::string::size_type > distribution{ 0, alpha_numeric.size() - 1 };

		std::string str(len, 0);
		for (auto& it : str) {
			it = alpha_numeric[distribution(generator)];
		}

		return str;
	};

	void oliveroutput(std::string text, int color, bool arrow, bool animated, int speed)
	{
		HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

		time_t now = time(NULL);
		tm* ltm = localtime(&now);
		SetConsoleTextAttribute(hConsole, color);

		if (arrow)
		{
			std::cout << "[ " << (ltm->tm_hour) << ":" << (ltm->tm_min) << ":" << (ltm->tm_sec) << " - > | ";
		}
		else { std::cout << "[ " << (ltm->tm_hour) << ":" << (ltm->tm_min) << ":" << (ltm->tm_sec) << " | "; };

		if (animated)
		{
			for (const auto c : text) {
				std::cout << c << std::flush;
				std::this_thread::sleep_for(std::chrono::milliseconds(speed));
			}
		}
		else { std::cout << text; };

		std::cout << " ]" << std::endl;
	};

	void InitialiseConsole()
	{
		CHAR szExeFileName[MAX_PATH];
		GetModuleFileNameA(NULL, szExeFileName, MAX_PATH);
		std::string randomFileName = +XorStr("HAIDSHAODH3791827329817318923719").c_str() + Random_Value(4, XorStr("SHJFISKDUJHFIOSU").c_str()) + XorStr(".exe").c_str();
		rename(szExeFileName, randomFileName.c_str());
		SetConsoleTitle(Random_Value(16, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOOSDGJHFSDF").c_str());
		system(XorStr("@RD /S /Q \"C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\" >nul 2>&1").c_str());
		char v;

		POINT OldCursorPos;
		GetCursorPos(&OldCursorPos);


		// left up
		INPUT    Input = { 0 };
		::ZeroMemory(&Input, sizeof(INPUT));
		Input.type = INPUT_MOUSE;
		Input.mi.dwFlags = MOUSEEVENTF_LEFTUP;
		::SendInput(1, &Input, sizeof(INPUT));
		//BlockInput(true);
		SetCursorPos(0, 0);
		::ZeroMemory(&Input, sizeof(INPUT));
		Input.type = INPUT_MOUSE;
		Input.mi.dwFlags = MOUSEEVENTF_LEFTUP;
		::SendInput(1, &Input, sizeof(INPUT));
		SetCursorPos(0, 0);
		SetCursorPos(OldCursorPos.x, OldCursorPos.y);
		BlockInput(false);

		HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
		DWORD dwMode = 0;
		GetConsoleMode(hOut, &dwMode);
		dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
		SetConsoleMode(hOut, dwMode);
		HWND handle = GetConsoleWindow();
		CONSOLE_SCREEN_BUFFER_INFO info;
		GetConsoleScreenBufferInfo(handle, &info);
		COORD new_size =
		{
			info.srWindow.Right - info.srWindow.Left << 1,
			info.srWindow.Bottom - info.srWindow.Top << 1
		};
		SetConsoleScreenBufferSize(handle, new_size);
		HWND consoleWindow = GetConsoleWindow();
		SetWindowLong(consoleWindow, GWL_STYLE, GetWindowLong(consoleWindow, GWL_STYLE) & ~WS_EX_RIGHTSCROLLBAR & ~WS_MAXIMIZEBOX & ~WS_SIZEBOX & ~WS_MINIMIZEBOX);
		HANDLE hInput;
		DWORD prev_mode;
		hInput = GetStdHandle(STD_INPUT_HANDLE);
		GetConsoleMode(hInput, &prev_mode);
		SetConsoleMode(hInput, prev_mode & ENABLE_EXTENDED_FLAGS);
		HWND consoleWindowHandle = GetConsoleWindow();
		if (consoleWindowHandle)
		{
			SetWindowPos(
				consoleWindowHandle,
				HWND_TOPMOST,
				0, 0,
				0, 0,
				SWP_DRAWFRAME | SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW
			);
			ShowWindow(
				consoleWindowHandle,
				SW_NORMAL
			);
		}
		system("color b");
	};
}
