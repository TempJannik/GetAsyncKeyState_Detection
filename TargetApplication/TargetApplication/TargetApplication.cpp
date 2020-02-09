// TargetApplication.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "Windows.h"
#include "apihook.h"
#include <stdio.h>
#include <intrin.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#pragma comment (lib, "wintrust")

typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation,
	MemoryWorkingSetList,
	MemorySectionName
} MEMORY_INFORMATION_CLASS;

typedef LONG(WINAPI* ZWQUERYVIRTUALMEMORY)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	PVOID MemoryInformation,
	ULONG MemoryInformationLength,
	PULONG ReturnLength
	);

struct UNICODE_STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	PWSTR    Buffer;
};

typedef UNICODE_STRING* PUNICODE_STRING;

typedef struct _FUNCTION_INFORMATION {
	char name[64];
	ULONG_PTR VirtualAddress;
} FUNCTION_INFORMATION, * PFUNCTION_INFORMATION;


typedef struct _MODULE_INFORMATION
{
	PVOID BaseAddress;
	PVOID AllocationBase;
	DWORD AllocationProtect;
	SIZE_T RegionSize;
	DWORD State;
	DWORD Protect;
	DWORD Type;
	WCHAR szPathName[MAX_PATH];
	PVOID EntryAddress;
	PFUNCTION_INFORMATION Functions;
	DWORD FunctionCount;
	DWORD SizeOfImage;
}MODULE_INFORMATION, * PMODULE_INFORMATION;

typedef SHORT(WINAPI* hGetAsyncKeyState)(int vKey);
hGetAsyncKeyState oGetAsyncKeyState;

BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
{
	LONG lStatus;
	DWORD dwLastError;

	
	WINTRUST_FILE_INFO FileData;
	memset(&FileData, 0, sizeof(FileData));
	FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileData.pcwszFilePath = pwszSourceFile;
	FileData.hFile = NULL;
	FileData.pgKnownSubject = NULL;

	
	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WinTrustData;

	memset(&WinTrustData, 0, sizeof(WinTrustData));

	WinTrustData.cbStruct = sizeof(WinTrustData);

	WinTrustData.pPolicyCallbackData = NULL;

	WinTrustData.pSIPClientData = NULL;

	WinTrustData.dwUIChoice = WTD_UI_NONE;

	WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

	WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

	WinTrustData.hWVTStateData = NULL;

	WinTrustData.pwszURLReference = NULL;

	WinTrustData.dwUIContext = 0;

	WinTrustData.pFile = &FileData;

	lStatus = WinVerifyTrust(
		NULL,
		&WVTPolicyGUID,
		&WinTrustData);

	switch (lStatus)
	{
		case ERROR_SUCCESS:
			return true;

		case TRUST_E_NOSIGNATURE:
			return false;
	}

	return true;
}

SHORT WINAPI mGetAsyncKeyState(int vKey)
{
	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());

	MODULEENTRY32 me32;
	BYTE szBuffer[MAX_PATH * 2 + 4] = { 0 };
	WCHAR szModuleName[MAX_PATH] = { 0 };
	WCHAR szPathName[MAX_PATH] = { 0 };
	MEMORY_BASIC_INFORMATION mbi;
	MODULE_INFORMATION mi;
	PUNICODE_STRING usSectionName;
	ULONG_PTR dwStartAddr;
	me32.dwSize = sizeof(MODULEENTRY32);

	ZWQUERYVIRTUALMEMORY fnZwQueryVirtualMemory;
	fnZwQueryVirtualMemory = (ZWQUERYVIRTUALMEMORY)::GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQueryVirtualMemory");

	if (fnZwQueryVirtualMemory(hProcess, (PVOID)_ReturnAddress(), MemoryBasicInformation, &mbi, sizeof(mbi), 0) >= 0)
	{
		if (mbi.Type != MEM_IMAGE)
			std::cout << "GetAsyncKeyState returning to a non image page" << std::endl;
		else
		{
			HMODULE hMods[1024];
			HANDLE hProcess;
			DWORD cbNeeded;
			unsigned int i;


			hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
				PROCESS_VM_READ,
				FALSE, GetCurrentProcessId());

			if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
			{
				for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
				{
					TCHAR szModName[MAX_PATH];

					if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
						sizeof(szModName) / sizeof(TCHAR)))
					{
						if (GetModuleHandle(szModName) == mbi.AllocationBase)
						{
							std::cout << "GetAsyncKeyState caller: " << szModName << std::endl;
							int wchars_num = MultiByteToWideChar(CP_UTF8, 0, szModName, -1, NULL, 0);
							wchar_t* wstr = new wchar_t[wchars_num];
							MultiByteToWideChar(CP_UTF8, 0, szModName, -1, wstr, wchars_num);
							if (VerifyEmbeddedSignature(wstr))
							{
								std::cout << "Caller is signed" << std::endl;
							}
							else
							{
								std::cout << "Caller isnt signed!" << std::endl;
							}
						}
					}
				}
			}

			CloseHandle(hProcess);
		}
	}

	std::cout << "GAKS called, key: " << vKey << " return add: "<< _ReturnAddress() << " add of ret add: " << _AddressOfReturnAddress() << std::endl;
	return oGetAsyncKeyState(vKey);
}

using namespace hook;
hook_t Hook;

int main()
{
	//Sleep(10000);
	char val1[] = "user32.dll";
	char val2[] = "GetAsyncKeyState";
	InitializeHook(&Hook, val1, val2, mGetAsyncKeyState);
	oGetAsyncKeyState = (hGetAsyncKeyState)Hook.APIFunction;
	InsertHook(&Hook);
	while (true)
	{
		Unhook(&Hook); //Reset hook because library is stupid, if you dont reset hook here it will only catch the CheatDll's call to GAKS if the dll was initialized before the hook was set
		FreeHook(&Hook);
		InitializeHook(&Hook, val1, val2, mGetAsyncKeyState);
		oGetAsyncKeyState = (hGetAsyncKeyState)Hook.APIFunction;
		InsertHook(&Hook);
		std::cout << "Trigger\n";
		Sleep(5000);
	}
    
}