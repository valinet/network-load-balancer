#pragma once
#include <Windows.h>

typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

DWORD GetSysWOW64Address(
	wchar_t* szFileName, 
	LPCSTR FunctionName
	);

BOOL moduleNameIsMonitored(
	wchar_t* moduleName
	);

void injectProcess(
	int processId, 
	DWORD pKernel32LoadLibraryWAddr, 
	BOOL bIs64BitProcess,
	LPFN_ISWOW64PROCESS fnIsWow64Process
	);