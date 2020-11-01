#pragma once
#include "pipe.h"
#include "http.h"
#include <cstddef>
#include <atlsecurity.h>
#include <string>




void RemoteExcution(int type)
{
    HANDLE hPipe;
    DWORD dwWritten;

  
        hPipe = CreateFile(TEXT("\\\\.\\pipe\\Pipe"),
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);

        if (hPipe != INVALID_HANDLE_VALUE)
        {
            if (type == 1337)
            {
                WriteFile(hPipe,
                    "0x1337",
                    6,
                    &dwWritten,
                    NULL);
            }

            else if (type == 6969)
            {
                WriteFile(hPipe,
                    "0x6969",
                    6,
                    &dwWritten,
                    NULL);
            }
        }

        CloseHandle(hPipe);

};

