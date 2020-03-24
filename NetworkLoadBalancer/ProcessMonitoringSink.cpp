#include <iostream>
#include <wbemidl.h>
#include <comutil.h>
#include <Psapi.h>
#pragma comment(lib, "wbemuuid.lib")

#include "ProcessMonitoringSink.h"

ULONG ProcessMonitoringSink::AddRef()
{
    return InterlockedIncrement(&m_lRef);
}

ULONG ProcessMonitoringSink::Release()
{
    LONG lRef = InterlockedDecrement(&m_lRef);
    if (lRef == 0)
        delete this;
    return lRef;
}

HRESULT ProcessMonitoringSink::QueryInterface(REFIID riid, void** ppv)
{
    if (riid == IID_IUnknown || riid == IID_IWbemObjectSink)
    {
        *ppv = (IWbemObjectSink*)this;
        AddRef();
        return WBEM_S_NO_ERROR;
    }
    else return E_NOINTERFACE;
}


HRESULT ProcessMonitoringSink::Indicate(long lObjCount, IWbemClassObject** pArray)
{
    for (long i = 0; i < lObjCount; i++)
    {
        IWbemClassObject* pObj = pArray[i];
        HRESULT hr = NULL;
        _variant_t vtProp;

        hr = pObj->Get(_bstr_t(L"TargetInstance"), 0, &vtProp, NULL, NULL);
        if (!FAILED(hr)) {
            IUnknown* str = vtProp;
            hr = str->QueryInterface(IID_IWbemClassObject, reinterpret_cast<void**>(&pArray[i]));
            if (SUCCEEDED(hr)) {
                _variant_t cn;
                hr = pArray[i]->Get(L"Name", 0, &cn, NULL, NULL);
                if (SUCCEEDED(hr))
                {
                    if (!((cn.vt == VT_NULL) || (cn.vt == VT_EMPTY)))
                    {
                        if (moduleNameIsMonitored(cn.bstrVal))
                        {
                            VariantClear(&cn);
                            hr = pArray[i]->Get(L"ProcessId", 0, &cn, NULL, NULL);
                            if (SUCCEEDED(hr))
                            {
                                if (!((cn.vt == VT_NULL) || (cn.vt == VT_EMPTY)))
                                {
                                    injectProcess(
                                        cn.intVal, 
                                        pKernel32LoadLibraryWAddr, 
                                        bIs64BitProcess,
                                        fnIsWow64Process,
                                        pDllMainAddr,
                                        hInjection
                                        );
                                }
                            }
                            VariantClear(&cn);
                        }
                        else
                        {
                            VariantClear(&cn);
                        }
                    }
                }
            }
            VariantClear(&vtProp);
        }
        // ... use the object.

        // AddRef() is only required if the object will be held after
        // the return to the caller.
    }

    return WBEM_S_NO_ERROR;
}

HRESULT ProcessMonitoringSink::SetStatus(
    /* [in] */ LONG lFlags,
    /* [in] */ HRESULT hResult,
    /* [in] */ BSTR strParam,
    /* [in] */ IWbemClassObject __RPC_FAR* pObjParam
    )
{
    printf("QuerySink::SetStatus hResult = 0x%X\n", hResult);
    return WBEM_S_NO_ERROR;
}