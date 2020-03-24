#include <iostream>
#include <Windows.h>
#include <shlwapi.h>
#include <Psapi.h>
#include <assert.h>
#pragma comment(lib, "Shlwapi.lib")

#include "utility.h"

BOOL moduleNameIsMonitored(wchar_t* moduleName) {
    if (wcsstr(moduleName, L"IDMan.exe") || wcsstr(moduleName, L"qbittorrent.exe")) {
        return TRUE;
    }
    return FALSE;
}

BOOL IsWOW64Process3(wchar_t* szFileName)
{
    BOOL ret = FALSE;

    HANDLE hFile;
    HANDLE hFileMapping;
    LPVOID lpFileBase;

    PIMAGE_DOS_HEADER pIDH;
    PIMAGE_NT_HEADERS32 pINH;

    hFile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("CreateFile failed in read mode.\n");
        goto step1Failed;
    }

    hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hFileMapping == 0)
    {
        printf("CreateFileMapping failed.\n");
        goto step2Failed;
    }

    lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (lpFileBase == 0)
    {
        printf("MapViewOfFile failed.\n");
        goto step3Failed;
    }

    pIDH = (PIMAGE_DOS_HEADER)lpFileBase;
    if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("File is not a valid DOS image.\n");
        goto RET;
    }

    pINH = (PIMAGE_NT_HEADERS32)((u_char*)pIDH + pIDH->e_lfanew);
    if (pINH->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("File is not a valid NT image.\n");
        goto RET;
    }

    if (pINH->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
    {
        ret = TRUE;
    }

RET:
    UnmapViewOfFile(lpFileBase);
step3Failed:
    CloseHandle(hFileMapping);
step2Failed:
    CloseHandle(hFile);
step1Failed:
    return ret;

}

// https://stackoverflow.com/questions/8776437/c-injecting-32-bit-targets-from-64-bit-process
// https://stackoverflow.com/questions/9955744/getting-offset-in-file-from-rva
// http://www.rohitab.com/discuss/topic/40594-parsing-pe-export-table/
// https://gist.github.com/juntalis/6041743
// https://stackoverflow.com/questions/2975639/resolving-rvas-for-import-and-export-tables-within-a-pe-file
DWORD GetSysWOW64Address(wchar_t* szFileName, LPCSTR FunctionName)
{
    DWORD ret = NULL;

    PIMAGE_DOS_HEADER pIDH;
    PIMAGE_NT_HEADERS32 pINH;
    PIMAGE_EXPORT_DIRECTORY exportsTable;
    PIMAGE_SECTION_HEADER sectionHeader;
    int32_t offset;

    DWORD* addressOfNames;
    WORD* addressOfNameOrdinals;
    PDWORD* addressOfFunctions;

    UINT i;

    HANDLE hFile;
    HANDLE hFileMapping;
    LPVOID lpFileBase;

    DWORD ptr;
    UINT nSectionCount;
    PBYTE baseImage;

    hFile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("CreateFile failed in read mode.\n");
        goto step1Failed;
    }

    hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hFileMapping == 0)
    {
        printf("CreateFileMapping failed.\n");
        goto step2Failed;
    }

    lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (lpFileBase == 0)
    {
        printf("MapViewOfFile failed.\n");
        goto step3Failed;
    }

    baseImage = (PBYTE)lpFileBase;
    pIDH = (PIMAGE_DOS_HEADER)lpFileBase;
    if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("File is not a valid DOS image.\n");
        goto RET;
    }

    pINH = (PIMAGE_NT_HEADERS32)((u_char*)pIDH + pIDH->e_lfanew);
    if (pINH->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("File is not a valid NT image.\n");
        goto RET;
    }

    if (pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
    {
        printf("VA of image is 0.\n");
        goto RET;
    }

    ptr = pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    sectionHeader = IMAGE_FIRST_SECTION(pINH);
    nSectionCount = pINH->FileHeader.NumberOfSections;
    for (i = 0; i <= nSectionCount; ++i, ++sectionHeader)
    {
        if ((sectionHeader->VirtualAddress) > ptr)
        {
            sectionHeader--;
            break;
        }
    }
    if (i > nSectionCount)
    {
        sectionHeader = IMAGE_FIRST_SECTION(pINH);
        UINT nSectionCount = pINH->FileHeader.NumberOfSections;
        for (i = 0; i < nSectionCount - 1; ++i, ++sectionHeader);
    }
    offset = (int32_t)sectionHeader->PointerToRawData - (int32_t)sectionHeader->VirtualAddress;

    exportsTable = (PIMAGE_EXPORT_DIRECTORY)(baseImage + offset + ptr);
    addressOfNames = (DWORD*)(baseImage + offset + exportsTable->AddressOfNames);
    addressOfNameOrdinals = (WORD*)(baseImage + offset + exportsTable->AddressOfNameOrdinals);
    addressOfFunctions = (PDWORD*)(baseImage + offset + exportsTable->AddressOfFunctions);

    for (i = 0; i < exportsTable->NumberOfFunctions; i++)
    {
        if (!strcmp(FunctionName, (char*)(baseImage + offset + addressOfNames[i])))
        {
            ret = *((DWORD*)(baseImage +
                offset +
                exportsTable->AddressOfFunctions +
                (DWORD)(addressOfNameOrdinals[i] * 4))
                );
            goto RET;
        }
    }

RET:
    UnmapViewOfFile(lpFileBase);
step3Failed:
    CloseHandle(hFileMapping);
step2Failed:
    CloseHandle(hFile);
step1Failed:
    return ret;
}

void injectProcess(
    int processId, 
    DWORD pKernel32LoadLibraryWAddr, 
    BOOL bIs64BitProcess,
    LPFN_ISWOW64PROCESS fnIsWow64Process,
    DWORD pDllMainAddr,
    uint64_t hInjection
    ) 
{
    wchar_t szLibPath[_MAX_PATH];
    wchar_t szTmpLibPath[_MAX_PATH];
    wchar_t szSysDir[_MAX_PATH];
    HANDLE hThread = NULL;
    void* pLibRemote = NULL;
    DWORD hLibModule = 0;
    HMODULE hKernel32 = NULL;
    HANDLE hProcess = NULL;
    BOOL bResult = FALSE;
    DWORD res = 0;
    FARPROC hAdrLoadLibrary = NULL;
    HMODULE* hMods = NULL;
    DWORD hModuleArrayInitialBytesInitial = 100 * sizeof(HMODULE);
    DWORD hModuleArrayInitialBytes = hModuleArrayInitialBytesInitial;
    DWORD hModuleArrayBytesNeeded = 0;
    SIZE_T i = 0;
    DWORD cbNeeded;


    hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        processId
        );
    if (hProcess == NULL) {
        return;
    }
    assert(hProcess != NULL);

    GetModuleFileName(
        GetModuleHandle(NULL),
        szLibPath,
        _MAX_PATH
        );
    PathRemoveFileSpec(szLibPath);
    lstrcat(
        szLibPath,
        L"\\NetworkLoadBalancerLibrary"
        );
    res = GetModuleFileNameEx(
        hProcess,
        NULL,
        szTmpLibPath,
        _MAX_PATH
        );
    assert(res != NULL);
    if (NULL != fnIsWow64Process) 
    {
        res = fnIsWow64Process(hProcess, &bResult);
        assert(res == TRUE);
    }
    if (bResult && bIs64BitProcess)
    {
        hModuleArrayInitialBytes = hModuleArrayInitialBytesInitial;
        hMods = (HMODULE*)calloc(
            hModuleArrayInitialBytes, 1
            );

        bResult = EnumProcessModulesEx(
            hProcess,
            hMods,
            hModuleArrayInitialBytes,
            &hModuleArrayBytesNeeded,
            LIST_MODULES_32BIT
            );
        assert(bResult == TRUE);
        if (hModuleArrayInitialBytes < hModuleArrayBytesNeeded)
        {
            hMods = (HMODULE*)realloc(
                hMods,
                hModuleArrayBytesNeeded
                );
            hModuleArrayInitialBytes = hModuleArrayBytesNeeded;
            bResult = EnumProcessModulesEx(
                hProcess,
                hMods,
                hModuleArrayInitialBytes,
                &hModuleArrayBytesNeeded,
                LIST_MODULES_32BIT
                );
            assert(bResult == TRUE);
        }
        GetSystemDirectory(szSysDir, _MAX_PATH);
        CharLower(szSysDir);
        if (szSysDir[lstrlen(szSysDir) - 1] != '\\')
        {
            lstrcat(szSysDir, L"\\");
        }
        lstrcat(szSysDir, L"kernel32.dll");
        for (i = 0; i < hModuleArrayBytesNeeded / sizeof(HMODULE); ++i)
        {
            GetModuleFileNameEx(hProcess, hMods[i], szTmpLibPath, _MAX_PATH);
            CharLower(szTmpLibPath);
            if (wcsstr(szTmpLibPath, szSysDir))
            {
                hKernel32 = hMods[i];
                hAdrLoadLibrary = (FARPROC)((DWORD)hKernel32 + pKernel32LoadLibraryWAddr);
                break;
            }
        }
        lstrcat(
            szLibPath,
            L"Win32.dll"
            );
        free(hMods);
    }
    else
    {
        hKernel32 = GetModuleHandle(L"Kernel32");
        assert(hKernel32 != NULL);

        hAdrLoadLibrary = GetProcAddress(
            hKernel32,
            "LoadLibraryW"
            );
        assert(hAdrLoadLibrary != NULL);

        if (bIs64BitProcess)
        {
            lstrcat(
                szLibPath,
                L"x64.dll"
                );
        }
        else
        {
            bResult = TRUE;
            if (NULL != fnIsWow64Process)
            {
                res = fnIsWow64Process(hProcess, &bResult);
                assert(res == TRUE);
            }
            if (!bResult)
            {
                CloseHandle(hProcess);
                std::cout << "On x64, please compile and run this " <<
                    "application for 64-bit. Won't inject into 64-bit " <<
                    "process from 32-bit module." << std::endl;
                return;
            }
            else
            {
                lstrcat(
                    szLibPath,
                    L"Win32.dll"
                    );
            }
        }
    }

    pLibRemote = VirtualAllocEx(
        hProcess,
        NULL,
        sizeof(szLibPath),
        MEM_COMMIT,
        PAGE_READWRITE
        );
    assert(pLibRemote != NULL);
    bResult = WriteProcessMemory(
        hProcess,
        pLibRemote,
        (void*)szLibPath,
        sizeof(szLibPath),
        NULL
        );
    assert(bResult == TRUE);
    hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)hAdrLoadLibrary,
        pLibRemote,
        0,
        NULL
        );
    assert(hThread != NULL);
    WaitForSingleObject(
        hThread,
        INFINITE
        );
    GetExitCodeThread(
        hThread,
        &hLibModule
        );
    assert(hLibModule != NULL);
    VirtualFreeEx(
        hProcess,
        (LPVOID)pLibRemote,
        0,
        MEM_RELEASE
        );

    if (NULL != fnIsWow64Process) 
    {
        res = fnIsWow64Process(hProcess, &bResult);
        assert(res == TRUE);
    }
    if (bResult && bIs64BitProcess)
    {
        hInjection = pDllMainAddr;
    }
    hModuleArrayInitialBytes = hModuleArrayInitialBytesInitial;
    hMods = (HMODULE*)calloc(
        hModuleArrayInitialBytes, 1
        );
    bResult = EnumProcessModulesEx(
        hProcess,
        hMods,
        hModuleArrayInitialBytes,
        &hModuleArrayBytesNeeded,
        LIST_MODULES_ALL
        );
    assert(bResult == TRUE);
    if (hModuleArrayInitialBytes < hModuleArrayBytesNeeded)
    {
        hMods = (HMODULE*)realloc(
            hMods,
            hModuleArrayBytesNeeded
            );
        hModuleArrayInitialBytes = hModuleArrayBytesNeeded;
        bResult = EnumProcessModulesEx(
            hProcess,
            hMods,
            hModuleArrayInitialBytes,
            &hModuleArrayBytesNeeded,
            LIST_MODULES_ALL
            );
        assert(bResult == TRUE);
    }
    CharLower(szLibPath);
    for (i = 0; i < hModuleArrayBytesNeeded / sizeof(HMODULE); ++i)
    {
        bResult = GetModuleFileNameEx(hProcess, hMods[i], szTmpLibPath, _MAX_PATH);
        CharLower(szTmpLibPath);
        if (wcsstr(szTmpLibPath, szLibPath))
        {
            break;
        }
    }
    hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)((uint64_t)hMods[i] + (uint64_t)hInjection),
        NULL,
        0,
        NULL
        );
    WaitForSingleObject(
        hThread,
        INFINITE
        );
    GetExitCodeThread(
        hThread,
        &hLibModule
        );
    assert(hLibModule != NULL);
    free(hMods);

    wprintf(L">>> Injected %s into PID: %d.\n", szLibPath, processId);

    CloseHandle(hProcess);
}