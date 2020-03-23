#define _WIN32_DCOM
#include <iostream>
#include <wbemidl.h>
#include <comdef.h>
#include <iphlpapi.h>
#include <unordered_map> 
#include <vector>
#pragma comment(lib, "Iphlpapi.lib")

#include "common.h"
#include "ProcessMonitoringSink.h"

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

struct NICInfo
{
    DWORD totalBytes;
    double speed;
    MIB_IPFORWARDROW routeInfo;
    UINT connections;
};

struct WindowProcInfo 
{
    UINT msgId;
    std::unordered_map<std::wstring, NICInfo>* adapters;
    HANDLE ghAdaptersMutex;
    UINT* balancing_policy;
};

struct NetworkRefreshrerParams
{
    IWbemRefresher* pRefresher;
    IWbemHiPerfEnum* pEnum;
    std::unordered_map<std::wstring, NICInfo>* adapters;
    HANDLE ghAdaptersMutex;
    int* sample_duration;
    UINT* balancing_policy;
};

// https://stackoverflow.com/questions/10737644/convert-const-char-to-wstring
std::wstring s2ws(const std::string& str)
{
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

DWORD WINAPI refreshNetworkData(
    LPVOID param
    )
{
    NetworkRefreshrerParams* params = reinterpret_cast<NetworkRefreshrerParams*>(param);
    std::unordered_map<std::wstring, NICInfo>* adapters = params->adapters;
    HANDLE ghAdaptersMutex = params->ghAdaptersMutex;
    IWbemRefresher* pRefresher = params->pRefresher;
    IWbemHiPerfEnum* pEnum = params->pEnum;
    int* sample_duration = params->sample_duration;
    UINT* balancing_policy = params->balancing_policy;
    IWbemObjectAccess** apEnumAccess = NULL;
    HRESULT hr;
    ULONGLONG startTime, endTime;

    DWORD dwNumObjects = 0;
    DWORD dwNumReturned = 0;

    wchar_t szName[_MAX_PATH];
    long dwNameReadLength = 0;
    DWORD dwBytesTotalPerSec = 0;

    long lNameHandle = 0;
    long lBytesTotalPerSec = 0;
    DWORD i = 0;
    int x = 0;

    PMIB_IPFORWARDTABLE pIpForwardTable;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;

    char szDestIp[128];
    char szMaskIp[128];
    char szGatewayIp[128];

    struct in_addr IpAddr;

    DWORD dwWaitResult;

    std::vector<MIB_IPFORWARDROW> unorderedAdapters;

    pIpForwardTable =
        (MIB_IPFORWARDTABLE*)MALLOC(sizeof(MIB_IPFORWARDTABLE));
    if (pIpForwardTable == NULL) {
        printf("Error allocating memory\n");
        return 0;
    }

    if (GetIpForwardTable(pIpForwardTable, &dwSize, 0) ==
        ERROR_INSUFFICIENT_BUFFER) {
        FREE(pIpForwardTable);
        pIpForwardTable = (MIB_IPFORWARDTABLE*)MALLOC(dwSize);
        if (pIpForwardTable == NULL) {
            printf("Error allocating memory\n");
            return 0;
        }
    }

    /* Note that the IPv4 addresses returned in
     * GetIpForwardTable entries are in network byte order
     */
    if ((dwRetVal = GetIpForwardTable(pIpForwardTable, &dwSize, 0)) == NO_ERROR) {
        for (i = 0; i < (int)pIpForwardTable->dwNumEntries; i++) {
            /* Do not consider routes not going to Internet (0.0.0.0) */
            if (pIpForwardTable->table[i].dwForwardDest) {
                continue;
            }
            unorderedAdapters.push_back(pIpForwardTable->table[i]);
        }

        FREE(pIpForwardTable);
    }
    else {
        printf("\tGetIpForwardTable failed.\n");
        FREE(pIpForwardTable);
        return 0;
    }

    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;

    /* variables used to print DHCP time info */
    struct tm newtime;
    char buffer[32];
    errno_t error;

    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(sizeof(IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) {
        printf("Error allocating memory needed to call GetAdaptersinfo\n");
        return 0;
    }
    // Make an initial call to GetAdaptersInfo to get
    // the necessary size into the ulOutBufLen variable
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        FREE(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            printf("Error allocating memory needed to call GetAdaptersinfo\n");
            return 0;
        }
    }

    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        pAdapter = pAdapterInfo;
        while (pAdapter) {
            for (i = 0; i < unorderedAdapters.size(); ++i) {
                if (unorderedAdapters[i].dwForwardIfIndex == pAdapter->Index) {
                    size_t strlenName = strlen(pAdapter->Description);
                    for (size_t j = 0; j < strlenName; ++j) {
                        if (pAdapter->Description[j] == '(') pAdapter->Description[j] = '[';
                        else if (pAdapter->Description[j] == ')') pAdapter->Description[j] = ']';
                    }
                    std::wstring szAdapterName = s2ws(std::string(pAdapter->Description));
                    dwWaitResult = WaitForSingleObject(
                        ghAdaptersMutex,
                        INFINITE);
                    if (dwWaitResult == WAIT_OBJECT_0) {
                        (*adapters)[szAdapterName].routeInfo = unorderedAdapters[i];
                        (*adapters)[szAdapterName].speed = 0;
                        (*adapters)[szAdapterName].totalBytes = 0;
                        (*adapters)[szAdapterName].connections = 0;
                    }
                    ReleaseMutex(ghAdaptersMutex);
                    break;
                }
            }
            pAdapter = pAdapter->Next;
        }
    }
    else {
        printf("GetAdaptersInfo failed with error: %d\n", dwRetVal);
        return 0;
    }
    if (pAdapterInfo)
        FREE(pAdapterInfo);

    dwWaitResult = WaitForSingleObject(
        ghAdaptersMutex,
        INFINITE);
    if (dwWaitResult == WAIT_OBJECT_0) {
        for (auto x : (*adapters)) {
            x.second.routeInfo.dwForwardProto = MIB_IPPROTO_NETMGMT;
        }
        std::wstring balpol;
        switch (*balancing_policy)
        {
        case BALANCING_POLICY_ROUND_ROBIN:
        {
            balpol = NAME_BALANCING_POLICY_ROUND_ROBIN;
            break;
        }
        case BALANCING_POLICY_LEAST_CONNECTIONS:
            balpol = NAME_BALANCING_POLICY_LEAST_CONNECTIONS;
            break;
        }
        std::wcout << "Balancing these adapters:" << std::endl << 
            "Policy: " << balpol << std::endl <<
            "=========================" << std::endl;
        for (auto x : (*adapters)) {
            std::wcout << "--> " << x.first << std::endl;
        }
    }
    ReleaseMutex(ghAdaptersMutex);

    while (TRUE)
    {
        startTime = GetTickCount64();

        dwNumReturned = 0;
        dwBytesTotalPerSec = 0;
        dwNumObjects = 0;

        hr = pRefresher->Refresh(0L);
        if (FAILED(hr))
        {
            return 0;
        }

        hr = pEnum->GetObjects(0L,
            dwNumObjects,
            apEnumAccess,
            &dwNumReturned);
        // If the buffer was not big enough,
        // allocate a bigger buffer and retry.
        if (hr == WBEM_E_BUFFER_TOO_SMALL
            && dwNumReturned > dwNumObjects)
        {
            apEnumAccess = new IWbemObjectAccess * [dwNumReturned];
            if (NULL == apEnumAccess)
            {
                hr = E_OUTOFMEMORY;
                return 0;
            }
            SecureZeroMemory(apEnumAccess,
                dwNumReturned * sizeof(IWbemObjectAccess*));
            dwNumObjects = dwNumReturned;

            if (FAILED(hr = pEnum->GetObjects(0L,
                dwNumObjects,
                apEnumAccess,
                &dwNumReturned)))
            {
                return 0;
            }
        }
        else
        {
            if (hr == WBEM_S_NO_ERROR)
            {
                hr = WBEM_E_NOT_FOUND;
                return 0;
            }
        }

        // First time through, get the handles.
        if (0 == x)
        {
            CIMTYPE NameType;
            CIMTYPE BytesTotalPerSecType;
            hr = apEnumAccess[0]->GetPropertyHandle(
                L"Name",
                &NameType,
                &lNameHandle
                );
            if (FAILED(hr))
            {
                return 0;
            }
            hr = apEnumAccess[0]->GetPropertyHandle(
                L"BytesTotalPersec",
                &BytesTotalPerSecType,
                &lBytesTotalPerSec
                );
            if (FAILED(hr))
            {
                return 0;
            }
        }


        dwWaitResult = WaitForSingleObject(
            ghAdaptersMutex,
            INFINITE);
        if (dwWaitResult == WAIT_OBJECT_0) {
            for (i = 0; i < dwNumReturned; i++)
            {
                hr = apEnumAccess[i]->ReadPropertyValue(
                    lNameHandle,
                    _MAX_PATH,
                    &dwNameReadLength,
                    (BYTE*)szName
                    );
                if (FAILED(hr))
                {
                    return 0;
                }
                hr = apEnumAccess[i]->ReadDWORD(
                    lBytesTotalPerSec,
                    &dwBytesTotalPerSec
                    );
                if (FAILED(hr))
                {
                    return 0;
                }

                std::wstring szWName(szName);

                if ((*adapters).find(szWName) != (*adapters).end()) {
                    double interval = 1000.0 / (*sample_duration);
                    double prevBytes = (*adapters)[szWName].totalBytes;
                    double currBytes = dwBytesTotalPerSec;
                    double rate = (currBytes - prevBytes) * interval;
                    UINT connections = (*adapters)[szWName].connections;
                    (*adapters)[szWName].totalBytes = dwBytesTotalPerSec;
                    (*adapters)[szWName].speed = rate;
                }

                // Done with the object
                apEnumAccess[i]->Release();
                apEnumAccess[i] = NULL;
            }
            
        }
        ReleaseMutex(ghAdaptersMutex);

        if (NULL != apEnumAccess)
        {
            delete[] apEnumAccess;
            apEnumAccess = NULL;
        }

        endTime = GetTickCount64();

        // Sleep for some time.
        if (endTime - startTime > (*sample_duration))
        {
            printf(
                "Network sampling interval is too low (by %d msec).\n", 
                endTime - startTime - (*sample_duration)
                );
            Sleep((*sample_duration));
        }
        else
        {
            Sleep((*sample_duration) - (endTime - startTime));
        }
    }
}

inline WindowProcInfo* GetAppState(HWND hwnd)
{
    LONG_PTR ptr = GetWindowLongPtr(hwnd, GWLP_USERDATA);
    WindowProcInfo* pState = reinterpret_cast<WindowProcInfo*>(ptr);
    return pState;
}

LRESULT CALLBACK WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    WindowProcInfo* info = NULL;
    if (uMsg == WM_CREATE)
    {
        CREATESTRUCT* pCreate = reinterpret_cast<CREATESTRUCT*>(lParam);
        info = reinterpret_cast<WindowProcInfo*>(pCreate->lpCreateParams);
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)info);
        HINSTANCE hInstance = pCreate->hInstance;
    }
    else
    {
        info = GetAppState(hWnd);
    }
    if (info != NULL)
    {
        if (uMsg == info->msgId) {
            DWORD dwWaitResult = WaitForSingleObject(
                info->ghAdaptersMutex,
                INFINITE);
            if (dwWaitResult == WAIT_OBJECT_0) {
                UINT balancing_policy = (*info->balancing_policy);
                if (wParam != BALANCING_POLICY_DEFAULT)
                {
                    balancing_policy = wParam;
                }
                UINT minConnections = INT_MAX;
                std::wstring minNameRR;
                double minRate = INT_MAX;
                std::wstring minNameLC;
                for (auto x : (*info->adapters)) {
                    UINT connections = x.second.connections;
                    if (connections < minConnections)
                    {
                        minConnections = connections;
                        minNameRR = x.first;
                    }
                    if (x.second.speed < minRate)
                    {
                        minRate = x.second.speed;
                        minNameLC = x.first;
                    }
                    (*info->adapters)[x.first].routeInfo.dwForwardMetric1 = 45;
                }
                std::wstring balpol;
                switch (balancing_policy) {
                case BALANCING_POLICY_ROUND_ROBIN:
                {
                    if (minNameRR[0] != 0) {
                        (*info->adapters)[minNameRR].connections++;
                        (*info->adapters)[minNameRR].routeInfo.dwForwardMetric1 = 40;
                    }
                    balpol = NAME_BALANCING_POLICY_ROUND_ROBIN;
                    break;
                }
                case BALANCING_POLICY_LEAST_CONNECTIONS:
                {
                    if (minNameLC[0] != 0) {
                        (*info->adapters)[minNameLC].routeInfo.dwForwardMetric1 = 40;
                    }
                    balpol = NAME_BALANCING_POLICY_LEAST_CONNECTIONS;
                    break;
                }
                }
                for (auto x : (*info->adapters)) {
                    dwWaitResult = SetIpForwardEntry(&x.second.routeInfo);
                    if (x.second.routeInfo.dwForwardMetric1 == 40) {
                        std::wcout << "Using \"" << x.first << "\" (current load: " << x.second.speed << ", connections: " << x.second.connections << ", policy: " << balpol << ")." << std::endl;
                    }
                }
            }
            ReleaseMutex(info->ghAdaptersMutex);
            if ((*info->balancing_policy) == BALANCING_POLICY_LEAST_CONNECTIONS) {
                Sleep(100);
            }
            return -1;
        }
    }
    return DefWindowProc(hWnd, uMsg, wParam, lParam);
}


int WINAPI wWinMain(
    HINSTANCE hInstance, 
    HINSTANCE hPrevInstance, 
    PWSTR pCmdLine, 
    int nCmdShow
    )
{
    FILE* conout;
    HRESULT hr = 0;
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    IUnsecuredApartment* pUnsecApp = NULL;
    ProcessMonitoringSink* pSink = NULL;
    IUnknown* pStubUnk = NULL;
    IWbemObjectSink* pStubSink = NULL;
    IWbemRefresher* pRefresher = NULL;
    IWbemConfigureRefresher* pConfig = NULL;
    IWbemHiPerfEnum* pEnum = NULL;
    long lID = 0;
    std::unordered_map<std::wstring, NICInfo> adapters;
    HANDLE ghAdaptersMutex;
    NetworkRefreshrerParams params;
    HANDLE ht;
    int sample_duration = 1000;
    WNDCLASS wc = { };
    HWND hWnd = NULL;
    WindowProcInfo windowInfo;
    MSG msg = { };
    UINT balancing_policy = BALANCING_POLICY_LEAST_CONNECTIONS;

    // Step 0: ----------------------------------------------------------------
    // Show a console. --------------------------------------------------------
#ifdef _DEBUG
    if (!AllocConsole()) 
    {
        goto step0Failed;
    }
    if (freopen_s(&conout, "CONOUT$", "w", stdout))
    {
        goto step0Failed;
    }
#endif

    // Step 1: ----------------------------------------------------------------
    // Initialize COM. --------------------------------------------------------
    hr = CoInitializeEx(
        0, 
        COINIT_MULTITHREADED
        );
    if (FAILED(hr))
    {
        std::cout << "Failed to initialize COM library. Error code = 0x"
            << std::hex << hr << std::endl;
        goto step1Failed;
    }

    // Step 2: ----------------------------------------------------------------
    // Set general COM security levels ----------------------------------------
    hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_NONE,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
        );
    if (FAILED(hr))
    {
        std::cout << "Failed to initialize security. Error code = 0x"
            << std::hex << hr << std::endl;
        goto step2Failed;
    }

    // Step 3: ----------------------------------------------------------------
    // Obtain the initial locator to WMI --------------------------------------
    hr = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc
        );
    if (FAILED(hr))
    {
        std::cout << "Failed to create IWbemLocator object. "
            << "Err code = 0x"
            << std::hex << hr << std::endl;
        goto step3Failed;
    }

    // Step 4: ----------------------------------------------------------------
    // Connect to WMI through the IWbemLocator::ConnectServer method ----------
    // Connect to the local root\cimv2 namespace ------------------------------
    // and obtain pointer pSvc to make IWbemServices calls. -------------------
    hr = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc
        );
    if (FAILED(hr))
    {
        std::cout << "Could not connect. Error code = 0x"
            << std::hex << hr << std::endl;
        goto step4Failed;
    }

    // Step 5: ----------------------------------------------------------------
    // Set security levels on the proxy ---------------------------------------
    hr = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx 
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx 
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities 
        );
    if (FAILED(hr))
    {
        std::cout << "Could not set proxy blanket. Error code = 0x"
            << std::hex << hr << std::endl;
        goto step5Failed;
    }

    // Step 6: ----------------------------------------------------------------
    // Receive event notifications --------------------------------------------

    hr = CoCreateInstance(
        CLSID_UnsecuredApartment, 
        NULL,
        CLSCTX_LOCAL_SERVER, 
        IID_IUnsecuredApartment,
        (void**)&pUnsecApp
        );
    if (FAILED(hr))
    {
        std::cout << "Failed to create UnsecuredApartment object. "
            << "Err code = 0x"
            << std::hex << hr << std::endl;
        goto step5Failed;
    }
    
    pSink = new (std::nothrow) ProcessMonitoringSink;
    if (pSink == NULL) 
    {
        printf("Failed to alloc memory for sink.\n");
        goto step5Failed;
    }
    pSink->AddRef();

    pUnsecApp->CreateObjectStub(
        pSink, 
        &pStubUnk
        );

    pStubUnk->QueryInterface(
        IID_IWbemObjectSink,
        (void**)&pStubSink
        );
    if (FAILED(hr))
    {
        std::cout << "Failed to query UnSecApt object. "
            << "Err code = 0x"
            << std::hex << hr << std::endl;
        goto step6Failed;
    }

    // The ExecNotificationQueryAsync method will call
    // The EventQuery::Indicate method when an event occurs
    hr = pSvc->ExecNotificationQueryAsync(
        _bstr_t("WQL"),
        _bstr_t("SELECT * "
            "FROM __InstanceCreationEvent WITHIN 1 "
            "WHERE TargetInstance ISA 'Win32_Process'"),
        WBEM_FLAG_SEND_STATUS,
        NULL,
        pStubSink
        );

    // Check for errors.
    if (FAILED(hr))
    {
        printf("ExecNotificationQueryAsync failed "
            "with = 0x%X\n", hr);
        goto step6Failed;
    }

    // Step 7: ----------------------------------------------------------------
    // Subscribe to performance data ------------------------------------------

    hr = CoCreateInstance(
        CLSID_WbemRefresher,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_IWbemRefresher,
        (void**)&pRefresher
        );
    if (FAILED(hr))
    {
        std::cout << "Failed to create Refresher object. "
            << "Err code = 0x"
            << std::hex << hr << std::endl;
        goto step6Failed;
    }

    hr = pRefresher->QueryInterface(
        IID_IWbemConfigureRefresher,
        (void**)&pConfig
        );
    if (FAILED(hr))
    {
        std::cout << "Failed to query Refresher object. "
            << "Err code = 0x"
            << std::hex << hr << std::endl;
        goto step7Failed;
    }

    hr = pConfig->AddEnum(
        pSvc,
        L"Win32_PerfRawData_Tcpip_NetworkInterface",
        0,
        NULL,
        &pEnum,
        &lID
        );
    if (FAILED(hr))
    {
        std::cout << "Failed to AddEnum to config object. "
            << "Err code = 0x"
            << std::hex << hr << std::endl;
        goto step8Failed;
    }

    // Step 8: ----------------------------------------------------------------
    // Monitor network data async ---------------------------------------------
    ghAdaptersMutex = CreateMutex(
        NULL,              // default security attributes
        FALSE,             // initially not owned
        NULL);             // unnamed mutex
    if (ghAdaptersMutex == NULL)
    {
        printf("CreateMutex error: %d\n", GetLastError());
        goto step8Failed;
    }


    params.pRefresher = pRefresher;
    params.pEnum = pEnum;
    params.adapters = &adapters;
    params.ghAdaptersMutex = ghAdaptersMutex;
    params.sample_duration = &sample_duration;
    params.balancing_policy = &balancing_policy;
    ht = CreateThread(
        NULL, 
        0, 
        refreshNetworkData,
        reinterpret_cast<LPVOID>(&params), 
        0, 
        NULL
        );
    if (ht == NULL)
    {
        std::cout << "Unable to create network monitoring thread." << std::endl;
        goto step8Failed;
    }

    // Step 9: ----------------------------------------------------------------
    // Register monitoring window class and open it ---------------------------
    windowInfo.msgId = RegisterWindowMessage(CLASS_NAME);
    windowInfo.adapters = &adapters;
    windowInfo.ghAdaptersMutex = ghAdaptersMutex;
    windowInfo.balancing_policy = &balancing_policy;

    ChangeWindowMessageFilter(windowInfo.msgId, MSGFLT_ADD);
    wc.style = CS_DBLCLKS;
    wc.lpfnWndProc = WindowProc;
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    if (!RegisterClass(&wc))
    {
        std::cout << "Cannot register window class." << std::endl;
        goto step8Failed;
    }

    hWnd = CreateWindowEx(
        0,                      // Optional window styles
        CLASS_NAME,          // Window class
        TEXT(""),                    // Window text
        WS_OVERLAPPEDWINDOW,    // Window style
        // Size and position
        100,
        100,
        300,
        300,
        NULL,       // Parent window    
        NULL,       // Menu
        hInstance,  // Instance handle
        &windowInfo      // Additional application data
        );
    if (hWnd == NULL)
    {
        std::cout << "Cannot open window." << std::endl;
        goto step8Failed;
    }

    // Step 10: ---------------------------------------------------------------
    // Run the message loop ---------------------------------------------------
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    hr = pSvc->CancelAsyncCall(pStubSink);

step8Failed:
    pConfig->Release();
step7Failed:
    pRefresher->Release();
step6Failed:
    pUnsecApp->Release();
    pStubUnk->Release();
    pSink->Release();
    pStubSink->Release();
step5Failed:
    pSvc->Release();
step4Failed:
    pLoc->Release();
step3Failed:
step2Failed:
    CoUninitialize();
step1Failed:
step0Failed:
    return 0;
}