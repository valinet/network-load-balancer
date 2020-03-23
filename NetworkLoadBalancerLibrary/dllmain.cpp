// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <psapi.h>

#include "../NetworkLoadBalancer/common.h"

typedef void(WINAPI* tWS)();
void(WINAPI* pMyFunc)() = NULL;
BYTE replaced_socket[20];
HWND daemon;
UINT msgId;
UINT balancing_policy = 0;

void my_func()
{
#ifdef _WIN64
	my_func();
	my_func();
#endif
	//wchar_t buf[10];
	//wsprintf(buf, L"%d %d", daemon, msgId);
	//MessageBox(NULL, buf, buf, 0);
	SendMessage(daemon, msgId, balancing_policy , 0);
#ifdef _WIN64
	my_func();
	my_func();
#endif
    pMyFunc();
}

BOOL apply_patch(
	SIZE_T dwAddress, 
	SIZE_T pTarget, 
	SIZE_T* orig_size, 
	BYTE* replaced
	)
{
	DWORD dwOldValue, dwTemp;
#ifdef _WIN64
	// jmp with absolute address in rax, cannot do relative jump because difference may be larger than 31 bits on amd64
	std::uint8_t addr[8];
	memcpy(addr, &pTarget, sizeof(pTarget));
	std::uint8_t pWrite[] = { 0x48, 0xbf, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], 0xff, 0xe7, 0x90, 0x90, 0x90 }; // move absolute address to rdi
#else
	// jmp with relative offset (better if space constrained, no downside on IA-32)
	std::uint8_t pWrite[5];
	DWORD loc = (DWORD)((SIZE_T)pTarget - (dwAddress + sizeof(pWrite)));
	std::uint8_t addr[4];
	memcpy(addr, &loc, sizeof(loc));
	pWrite[0] = 0xe9;
	pWrite[1] = addr[0];
	pWrite[2] = addr[1];
	pWrite[3] = addr[2];
	pWrite[4] = addr[3];
#endif
	VirtualProtect((LPVOID)dwAddress, sizeof(SIZE_T), PAGE_EXECUTE_READWRITE, &dwOldValue);
	ReadProcessMemory(GetCurrentProcess(), (LPVOID)dwAddress, (LPVOID)replaced, sizeof(pWrite), (PSIZE_T)orig_size);
	BOOL bSuccess = WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddress, &pWrite, sizeof(pWrite), NULL);
	VirtualProtect((LPVOID)dwAddress, sizeof(SIZE_T), dwOldValue, &dwTemp);

	return bSuccess;
}

BOOL CALLBACK GetDaemon(
	_In_ HWND   hwnd,
	_In_ LPARAM lParam
	)
{
	HWND* daemon = reinterpret_cast<HWND*>(lParam);
	TCHAR name[100];
	GetClassName(hwnd, name, 100);
	if (wcsstr(name, CLASS_NAME)) {
		*daemon = hwnd;
		return FALSE;
	}
	return TRUE;
}

DWORD WINAPI initialize(
	LPVOID param
	)
{
	msgId = RegisterWindowMessage(CLASS_NAME);

	SIZE_T addr;
	BYTE replaced[20];
	SIZE_T orig_size;

	LoadLibrary(TEXT("WS2_32.dll"));
	SIZE_T addr_socket = (SIZE_T)GetProcAddress(GetModuleHandle(TEXT("WS2_32.dll")), "connect");
	SIZE_T orig_size_socket = 0;

	addr = addr_socket;
	if (apply_patch(addr, (SIZE_T)(&my_func), &orig_size_socket, replaced_socket))
	{
		pMyFunc = (tWS)VirtualAlloc(NULL, orig_size_socket << 2, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#ifdef _WIN64
		// preserve call stack (registers) during our function call
		BYTE pusha[] = { 0x41, 0x50, 0x52, 0x51, 0x41, 0x51, 0x48, 0x83, 0xEC, 0x28 }; // push r8; push rdx; push rcx; push r9; sub rsp, 28h
		BYTE popa[] = { 0x48, 0x83, 0xC4, 0x28, 0x41, 0x59, 0x59, 0x5a, 0x41, 0x58 }; // add rsp, 28h; pop r9; pop pop rcx; pop rdx; pop r8
		DWORD dwOldValue, dwOldValue2;
		VirtualProtect((LPVOID)&my_func, sizeof(SIZE_T), PAGE_EXECUTE_READWRITE, &dwOldValue);
		memcpy((void*)(((SIZE_T)&my_func) + 4), pusha, 10);
		memcpy((void*)(((SIZE_T)&my_func) + 43), popa, 10);
		VirtualProtect((LPVOID)&my_func, sizeof(SIZE_T), dwOldValue, &dwOldValue2);
#endif
		memcpy((void*)((SIZE_T)pMyFunc), replaced_socket, orig_size_socket);
		apply_patch((SIZE_T)pMyFunc + orig_size_socket, (SIZE_T)(addr + orig_size_socket), &orig_size, replaced);
	}
	EnumWindows(GetDaemon, reinterpret_cast<LPARAM>(&daemon));

	return 0;
}

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
    )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{
		TCHAR szFileName[_MAX_PATH];

		GetModuleBaseName(GetCurrentProcess(), GetModuleHandle(NULL), szFileName, _MAX_PATH);

		if (wcsstr(szFileName, L"IDMan.exe"))
		{
			balancing_policy = BALANCING_POLICY_ROUND_ROBIN;
		}

		//MessageBox(NULL, szFileName, L"Injected", 0);

		CreateThread(NULL, 0, initialize, NULL, 0, NULL);

		break;
	}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

