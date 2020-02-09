// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

DWORD WINAPI Repeat()
{
	while (true)
	{
		if (GetAsyncKeyState(0x4C)) //Close when L is pressed
		{
			ExitProcess(0);
		}
		Sleep(500);
	}
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Repeat, 0, 0, 0);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

