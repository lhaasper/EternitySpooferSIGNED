#include "../Headers.h"

#include "SizeOfImage.h"

// Any unreasonably large value will work say for example 0x100000 or 100,000h

VOID SizeOfImage()
{


	PPEB pPeb = (PPEB)__readgsqword(0x60);
	// The following pointer hackery is because winternl.h defines incomplete PEB types
	PLIST_ENTRY InLoadOrderModuleList = (PLIST_ENTRY)pPeb->Ldr->Reserved2[1]; // pPeb->Ldr->InLoadOrderModuleList
	PLDR_DATA_TABLE_ENTRY tableEntry = CONTAINING_RECORD(InLoadOrderModuleList, LDR_DATA_TABLE_ENTRY, Reserved1[0] /*InLoadOrderLinks*/);
	PULONG pEntrySizeOfImage = (PULONG)&tableEntry->Reserved3[1]; // &tableEntry->SizeOfImage
	*pEntrySizeOfImage = (ULONG)((INT_PTR)tableEntry->DllBase + 0x100000);
}
