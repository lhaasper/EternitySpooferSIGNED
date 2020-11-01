// Loader.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "../Loader/AntiDebug/Headers.h"
#include "ConsoleConfig.h"
#include "api.hpp"
using namespace c_auth;

std::string tm_to_readable_time(tm ctx) {
    char buffer[25];

    strftime(buffer, sizeof(buffer), "%m/%d/%y", &ctx);

    return std::string(buffer);
}
int main()
{
    std::string token;
	c_api::c_init(XorStr("1.0").c_str(), XorStr("LgcR1zOHfKoFE3Bu1Hrov5dpxFsiHgBXLCcHrFrdKil").c_str(), XorStr("cc028850726993c5308c84dc0aa62f07").c_str());
	system(XorStr("color b").c_str());
	printf(XorStr("\n\n Initialising!").c_str());
	InitiateSecurityProtocol();
    InitialiseConsole();
	likewiseprint("RED", "TEST");
    std::cin >> token;
    if (c_api::c_all_in_one(token)) {
        std::cout << "Logged in successfully !!!\n";

        std::cout << c_userdata::username << std::endl;
        std::cout << c_userdata::email << std::endl;
        std::cout << tm_to_readable_time(c_userdata::expires) << std::endl;
        std::cout << c_userdata::var << std::endl;
        std::cout << c_userdata::rank << std::endl;
    }
    else {
        std::cout << ":ddd !!!";
    }
	Spoof();
    printf(XorStr("\n Loaded!").c_str());
	std::cin.get();
    system(XorStr("pause > nul").c_str());
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
