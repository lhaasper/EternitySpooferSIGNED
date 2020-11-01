#include "../Headers.h"
#include "ErasePEHeaderFromMemory.h"

/* This function will erase the current images PE header from memory preventing a successful image if dumped */
	// Get base address of module
char* pBaseAddr = (char*)GetModuleHandle(NULL);

VOID ErasePEHeaderFromMemory()
{
	
	DWORD OldProtect = 0;

	// Change memory protection
	VirtualProtect(pBaseAddr, 4096, // Assume x86 page size
		PAGE_READWRITE, &OldProtect);

//	SecureZeroMemory(pBaseAddr, 4096);
}


