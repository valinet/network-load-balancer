#pragma once

#include <iostream>
#include <Windows.h>
#include <wbemidl.h>
#include <dbghelp.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Dbghelp.lib")

#include "utility.h"

class ProcessMonitoringSink : public IWbemObjectSink
{
    LONG m_lRef;
    bool bDone;
    BOOL bIs64BitProcess = FALSE;
    DWORD pKernel32LoadLibraryWAddr = 0;
    LPFN_ISWOW64PROCESS fnIsWow64Process = NULL;

public:
    ProcessMonitoringSink() 
    {
        fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
            GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

        // https://stackoverflow.com/questions/14184137/how-can-i-determine-whether-a-process-is-32-or-64-bit
        IMAGE_NT_HEADERS* headers = ImageNtHeader(GetModuleHandle(NULL));
        if (headers->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
        {
            bIs64BitProcess = TRUE;
            wchar_t szFileName[_MAX_PATH];
            GetSystemWow64Directory(
                szFileName,
                _MAX_PATH
                );
            lstrcat(
                szFileName,
                L"\\Kernel32.dll"
                );
            pKernel32LoadLibraryWAddr = GetSysWOW64Address(
                szFileName,
                "LoadLibraryW"
                );
        }
        
        m_lRef = 0; 
    }
    ~ProcessMonitoringSink() { bDone = TRUE; }

    virtual ULONG STDMETHODCALLTYPE AddRef();
    virtual ULONG STDMETHODCALLTYPE Release();
    virtual HRESULT STDMETHODCALLTYPE
        QueryInterface(REFIID riid, void** ppv);

    virtual HRESULT STDMETHODCALLTYPE Indicate(
        /* [in] */
        LONG lObjectCount,
        /* [size_is][in] */
        IWbemClassObject __RPC_FAR* __RPC_FAR* apObjArray
        );

    virtual HRESULT STDMETHODCALLTYPE SetStatus(
        /* [in] */ LONG lFlags,
        /* [in] */ HRESULT hResult,
        /* [in] */ BSTR strParam,
        /* [in] */ IWbemClassObject __RPC_FAR* pObjParam
        );
};