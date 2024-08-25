#include "ScyllaHideCE.h"
#include "..\PluginGeneric\Injector.h"

enum DbgMode { Open, Attach };
DbgMode dbgMode = Attach;
ExportedFunctions Exported;
int selfID;
int memorybrowserpluginid = -1; //initialize it to -1 to indicate failure (used by the DisablePlugin routine)
int debugpluginID = -1;
int disasmbCtxPluginID = -1;
MEMORYVIEWPLUGIN_INIT MEMVIEWPLUG_opt;
MEMORYVIEWPLUGIN_INIT MEMVIEWPLUG_InjDll;
MEMORYVIEWPLUGIN_INIT MEMVIEWPLUG_attOrStrt;
DEBUGEVENTPLUGIN_INIT DEBUGEVENTPLUGIN;
DISASSEMBLERCONTEXT_INIT DISASSEMBLERCONTEXT;

scl::Settings g_settings;
scl::Logger g_log;
std::wstring g_scyllaHideDllPath;
std::wstring g_scyllaHideIniPath;

HOOK_DLL_DATA g_hdd;
HINSTANCE hinst;
HMODULE hNtdllModule = 0;
bool specialPebFix = false;
DWORD ProcessId = 0;
DWORD LastProcessId = 0;
bool bHooked = false;

//link time
HWND hwndDlg;

int screenWidth;
int screenHeight;
float scalingFactor;

static LPVOID remoteImageBase = 0;


#ifdef _WIN64
const WCHAR g_scyllaHideDllFilename[] = L"HookLibraryx64.dll";
#else
const WCHAR g_scyllaHideDllFilename[] = L"HookLibraryx86.dll";
#endif

void showError(std::string errorMsg = "", bool getLast = true) {
    DWORD error;
    std::string lastErrMsg;
    if (getLast) {
        error = GetLastError();
        lastErrMsg = std::system_category().message(error);
        if (errorMsg[0]) {
            MessageBoxA(0, (errorMsg + "\n" + lastErrMsg).c_str(), "Error", MB_ICONERROR);
        }
        else {
            MessageBoxA(0, lastErrMsg.c_str(), "Error", MB_OK);
        }
    }
    else {
        MessageBoxA(0, errorMsg.c_str(), "Error", MB_OK);
    }
}

bool isProcAlive(DWORD procID)
{
    HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, ProcessId);

    DWORD ret = WaitForSingleObject(hProcess, 0);
    bool isAlive = ret == WAIT_TIMEOUT;
    CloseHandle(hProcess);
    return isAlive;
}

bool fixPeb(LPDEBUG_EVENT DebugEvent)
{
    bool result = false;

    if (g_settings.opts().fixPebHeapFlags)
    {
        if (specialPebFix)
        {
            result = StartFixBeingDebugged(ProcessId, false);
            specialPebFix = false;
        }

        if (DebugEvent->u.LoadDll.lpBaseOfDll == hNtdllModule)
        {
            result = StartFixBeingDebugged(ProcessId, true);
            specialPebFix = true;
        }
    }
    return result;
}

// forward declare for startInjectionProcessNoSuspend
bool StartHooking(HANDLE hProcess, HOOK_DLL_DATA* hdd, BYTE* dllMemory, DWORD_PTR imageBase);
void RestoreHooks(HOOK_DLL_DATA* hdd, HANDLE hProcess);

// SyllaHide's startInjectionProcess suspends all threads and then resumes them;
// This is incompatible when we are at EXIT_THREAD_DEBUG_EVENT and EXCEPTION_DEBUG_EVENT. so heres the modified version
void startInjectionProcessNoSuspend(HANDLE hProcess, HOOK_DLL_DATA* hdd, BYTE* dllMemory, bool newProcess)
{
    const bool injectDll = g_settings.hook_dll_needed() || hdd->isNtdllHooked || hdd->isKernel32Hooked || hdd->isUserDllHooked;
    DWORD hookDllDataAddressRva = GetDllFunctionAddressRVA(dllMemory, "HookDllData");

    if (!newProcess)
    {
        //g_log.Log(L"Apply hooks again");
        if (injectDll && StartHooking(hProcess, hdd, dllMemory, (DWORD_PTR)remoteImageBase))
        {
            WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)hookDllDataAddressRva + (DWORD_PTR)remoteImageBase), hdd, sizeof(HOOK_DLL_DATA), 0);
        }
        else if (!injectDll)
        {
            StartHooking(hProcess, hdd, nullptr, 0);
        }
    }
    else
    {
        if (g_settings.opts().removeDebugPrivileges)
        {
            RemoveDebugPrivileges(hProcess);
        }

        RestoreHooks(hdd, hProcess);

        if (injectDll)
        {
            remoteImageBase = MapModuleToProcess(hProcess, dllMemory, true);
            if (remoteImageBase)
            {
                FillHookDllData(hProcess, hdd);

                if (StartHooking(hProcess, hdd, dllMemory, (DWORD_PTR)remoteImageBase) &&
                    WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)hookDllDataAddressRva + (DWORD_PTR)remoteImageBase), hdd, sizeof(HOOK_DLL_DATA), 0))
                {
                    g_log.LogInfo(L"Hook injection successful, image base %p", remoteImageBase);
                }
                else
                {
                    g_log.LogError(L"Failed to write hook dll data");
                }
            }
            else
            {
                g_log.LogError(L"Failed to map image!");
            }
        }
        else
        {
            if (StartHooking(hProcess, hdd, nullptr, 0))
                g_log.LogInfo(L"PEB patch successful, hook injection not needed\n");
        }
    }
}

int AdjustGUISize(int baseSize, float scalingFactor) {
    return static_cast<int>(baseSize * scalingFactor);
}

wchar_t ProfName[256];
LRESULT CALLBACK getProfProcedure(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    static HWND hwndEdit, hwndButton;
    static HFONT hFont;

    switch (msg)
    {
    case WM_CREATE:
    {
        hFont = CreateFont(AdjustGUISize(25, scalingFactor), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET,
            OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
            DEFAULT_PITCH | FF_SWISS, L"Arial");

        hwndEdit = CreateWindowW(L"Edit", NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            AdjustGUISize(75, scalingFactor) , AdjustGUISize(20, scalingFactor), AdjustGUISize(250, scalingFactor), AdjustGUISize(30, scalingFactor),
            hwnd, (HMENU)1, NULL, NULL);

        const WCHAR* placeholderText = L"Profile Name here...";
        SendMessage(hwndEdit, (0x1500 + 1), 0, (LPARAM)placeholderText);  // (0x1500 + 1) = EM_SETCUEBANNER

        SendMessage(hwndEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

        hwndButton = CreateWindowW(L"Button", L"OK", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            AdjustGUISize(150, scalingFactor), AdjustGUISize(70, scalingFactor), AdjustGUISize(100, scalingFactor), AdjustGUISize(30, scalingFactor),
            hwnd, (HMENU)2, NULL, NULL);

        SendMessage(hwndButton, WM_SETFONT, (WPARAM)hFont, TRUE);

        break;
    }
    case WM_COMMAND:
    {
        if (LOWORD(wparam) == 2 && HIWORD(wparam) == BN_CLICKED)
        {
            GetWindowTextW(hwndEdit, ProfName, 256);
            PostMessage(hwnd, WM_CLOSE, 0, 0);
        }
        break;
    }
    case WM_DESTROY:
    {
        DeleteObject(hFont); // Clean up the font object
        PostQuitMessage(0);
        break;
    }
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

std::wstring getProfile() {
    MSG  msg;
    WNDCLASSW getProf_wc = { 0 };
    getProf_wc.lpszClassName = L"Profile Name";
    getProf_wc.hInstance = hinst;
    getProf_wc.hbrBackground = GetSysColorBrush(COLOR_3DFACE);
    getProf_wc.lpfnWndProc = getProfProcedure;
    getProf_wc.hCursor = LoadCursor(0, IDC_ARROW);

    RegisterClassW(&getProf_wc);

    screenWidth = GetSystemMetrics(SM_CXSCREEN);
    screenHeight = GetSystemMetrics(SM_CYSCREEN);
    scalingFactor = screenWidth / 1280.0f; // Assuming 1280 is the base resolution

    int windowWidth = AdjustGUISize(400, scalingFactor);
    int windowHeight = AdjustGUISize(150, scalingFactor);

    int posX = (screenWidth - windowWidth) / 2;
    int posY = (screenHeight - windowHeight) / 2;

    CreateWindowW(getProf_wc.lpszClassName, L"Enter profile name",
        (WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX) | WS_VISIBLE,
        posX, posY, windowWidth, windowHeight, 0, 0, hinst, 0);

    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (std::wstring)ProfName;
}


BOOL __stdcall MemViewPlug_attOrOpn(UINT_PTR* disassembleraddress, UINT_PTR* selected_disassembler_address, UINT_PTR* hexviewaddress)
{
    dbgMode = (DbgMode)!dbgMode;
    dbgMode == Attach ? MEMVIEWPLUG_attOrStrt.name = "ScyllaHideCE mode:   *Attach*" : MEMVIEWPLUG_attOrStrt.name = "ScyllaHideCE mode:   *Open*";
    Exported.UnregisterFunction(selfID, memorybrowserpluginid);
    memorybrowserpluginid = Exported.RegisterFunction(selfID, ptMemoryView, &MEMVIEWPLUG_attOrStrt);
    if (memorybrowserpluginid == -1)
    {
        showError("Failure to register the ondebugevent plugin", false);
        return FALSE;
    }
    return TRUE;
}


BOOL __stdcall disassemblercontextPopup(UINT_PTR selectedAddress, char** addressofname, BOOL* show) {
    *show = TRUE;
    return 0;
}

BOOL __stdcall disassemblercontext(UINT_PTR* selectedAddress)
{
    ProcessId = (DWORD) * (Exported.OpenedProcessID);

    if (isProcAlive(ProcessId)) {
        ZeroMemory(&g_hdd, sizeof(HOOK_DLL_DATA));
        ReadNtApiInformation(&g_hdd);
        DialogBox(hinst, MAKEINTRESOURCE(IDD_OPTIONS), NULL, &OptionsDlgProc);
        return TRUE;
    }
    else {
        showError("No process is open", false);
        return FALSE;
    }
}

BOOL __stdcall MemViewPlug_opt(UINT_PTR* disassembleraddress, UINT_PTR* selected_disassembler_address, UINT_PTR* hexviewaddress)
{
    ProcessId = (DWORD) * (Exported.OpenedProcessID);

    if (isProcAlive(ProcessId)) {
        ZeroMemory(&g_hdd, sizeof(HOOK_DLL_DATA));
        ReadNtApiInformation(&g_hdd);
        DialogBox(hinst, MAKEINTRESOURCE(IDD_OPTIONS), NULL, &OptionsDlgProc);
        return TRUE;
    }
    else {
        showError("No process is open", false);
        return FALSE;
    }
}

BOOL __stdcall MemViewPlug_InjDll(UINT_PTR* disassembleraddress, UINT_PTR* selected_disassembler_address, UINT_PTR* hexviewaddress)
{
    ProcessId = (DWORD) * (Exported.OpenedProcessID);

    if (isProcAlive(ProcessId)) {
        wchar_t dllPath[MAX_PATH] = {};
        if (scl::GetFileDialogW(dllPath, _countof(dllPath))) {
            injectDll(ProcessId, dllPath);
            return TRUE;
        }
        else {
            showError("Error on DLL opening the dll file");
            return FALSE;
        }
            
    }
    else {
        showError("No process is open", false);
        return FALSE;
    }
    
}

int __stdcall debugeventplugin(LPDEBUG_EVENT DebugEvent)
{
    HANDLE handle = *(Exported.OpenedProcessHandle);
    ProcessId = (DWORD) * (Exported.OpenedProcessID);

    if (!LastProcessId)
    {
        LastProcessId = ProcessId;
    }
    else if (LastProcessId != ProcessId)
    {
        bHooked = false;
        LastProcessId = ProcessId;
    }

    fixPeb(DebugEvent);

    switch (DebugEvent->dwDebugEventCode)
    {
    case CREATE_PROCESS_DEBUG_EVENT:
    {
        //will freeze the windows debugger as it will wait for peb->BeingDebugged to become true (when attaching) and we are setting it to false
        if (dbgMode == Open) {
            ProcessId = DebugEvent->dwProcessId;
            ZeroMemory(&g_hdd, sizeof(HOOK_DLL_DATA));

            if (DebugEvent->u.CreateProcessInfo.lpStartAddress == NULL)
            {
                if (g_settings.opts().killAntiAttach)
                {
                    if (!ApplyAntiAntiAttach(ProcessId))
                    {
                        showError("Anti-Anti-Attach failed");
                    }
                }
                if (!bHooked)
                {
                    ReadNtApiInformation(&g_hdd);

                    startInjection(ProcessId, &g_hdd, g_scyllaHideDllPath.c_str(), true);
                    bHooked = true;
                }
            }
            fixPeb(DebugEvent);
        }
        break;
    }

    case EXIT_THREAD_DEBUG_EVENT:
    {
        /*if (dbgMode == Attach) {
            ProcessId = DebugEvent->dwProcessId;
            bHooked = false;
            ZeroMemory(&g_hdd, sizeof(HOOK_DLL_DATA));

            if (DebugEvent->u.CreateProcessInfo.lpStartAddress == NULL)
            {
                if (g_settings.opts().killAntiAttach)
                {
                    if (!ApplyAntiAntiAttach(ProcessId))
                    {
                        showError("Anti-Anti-Attach failed");
                    }
                }
                if (!bHooked)
                {
                    ReadNtApiInformation(&g_hdd);

                    bHooked = true;
                    startInjection(ProcessId, &g_hdd, g_scyllaHideDllPath.c_str(), true);
                }
            }
        }
        break;*/
    }

    case LOAD_DLL_DEBUG_EVENT:
    {
        if (bHooked)
        {
            BYTE* dllMemory = ReadFileToMemory(g_scyllaHideDllPath.c_str());
            if (dllMemory)
            {
                startInjectionProcessNoSuspend(handle, &g_hdd, dllMemory, false);
                free(dllMemory);
            }
            else
            {
                g_log.LogError(L"Cannot find %s", g_scyllaHideDllPath.c_str());
                MessageBoxW(nullptr, L"Failed to load ScyllaHide hook library DLL! Make sure it is installed correctly and has not been deleted by an anti-virus.", L"Error", MB_ICONERROR);
            }

            fixPeb(DebugEvent);
        }
        break;
    }
    case EXCEPTION_DEBUG_EVENT:
    {
        // hoping to get the 0x80000003 that windows debugger sends
        // this means debugger is done attaching
        switch (DebugEvent->u.Exception.ExceptionRecord.ExceptionCode)
        {
        case STATUS_BREAKPOINT:
        {
            if (g_settings.opts().killAntiAttach)
            {
                if (!ApplyAntiAntiAttach(ProcessId))
                {
                    showError("Anti-Anti-Attach failed");
                }
            }

            //aat error
            if (!bHooked)
            {
                ZeroMemory(&g_hdd, sizeof(HOOK_DLL_DATA));
                ReadNtApiInformation(&g_hdd);

                //startInjection(ProcessId, &g_hdd, g_scyllaHideDllPath.c_str(), true);

                BYTE* dllMemory = ReadFileToMemory(g_scyllaHideDllPath.c_str());
                if (dllMemory)
                {
                    startInjectionProcessNoSuspend(handle, &g_hdd, dllMemory, true);
                    free(dllMemory);
                }
                else
                {
                    g_log.LogError(L"Cannot find %s", g_scyllaHideDllPath.c_str());
                    MessageBoxW(nullptr, L"Failed to load ScyllaHide hook library DLL! Make sure it is installed correctly and has not been deleted by an anti-virus.", L"Error", MB_ICONERROR);
                }

                bHooked = true;
            }
            fixPeb(DebugEvent);
            break;
        }
        }
        break;
    }
    }
    return 0;

    //ContinueDebugEvent(DebugEvent->dwProcessId, DebugEvent->dwThreadId, DBG_CONTINUE);
    //return 1; //if you dont want anything else handle the event
}


BOOL __stdcall CEPlugin_GetVersion(PPluginVersion pv, int sizeofpluginversion)
{
    pv->version = CESDK_VERSION;
    pv->pluginname = "ScyllaHideCE: hide cheat engine in usermode (SDK v4: 6.0+)";
    return TRUE;
}



BOOL __stdcall CEPlugin_InitializePlugin(PExportedFunctions ef, int pluginid)
{
    bHooked = false;
    selfID = pluginid;
    Exported = *ef; 
    if (Exported.sizeofExportedFunctions != sizeof(Exported)) {
        Exported.ShowMessage("Could not get Exported functions");
        return FALSE;
    }

    //scylla stuff
    hNtdllModule = GetModuleHandleW(L"ntdll.dll");
    auto wstrPath = scl::GetModuleFileNameW(hinst);
    wstrPath.resize(wstrPath.find_last_of(L'\\') + 1);
    g_scyllaHideDllPath = wstrPath + g_scyllaHideDllFilename;
    g_scyllaHideIniPath = wstrPath + L"ScyllaHideCE.ini";
    g_settings.Load(g_scyllaHideIniPath.c_str());

    auto log_file = wstrPath + L"ScyllaHideCE.log";
    g_log.SetLogFile(log_file.c_str());
    //g_log.SetLogCb(scl::Logger::Info, LogCallback);
    //g_log.SetLogCb(scl::Logger::Error, LogCallback);


    //memory browser plugin menu:
    MEMVIEWPLUG_opt.name = "ScyllaHideCE options";
    MEMVIEWPLUG_opt.callbackroutine = MemViewPlug_opt;
    MEMVIEWPLUG_opt.shortcut = "Ctrl+Q";
    memorybrowserpluginid = Exported.RegisterFunction(pluginid, ptMemoryView, &MEMVIEWPLUG_opt);
    if (memorybrowserpluginid == -1)
    {
        Exported.ShowMessage("Failure to register the memoryview plugin");
        return FALSE;
    }

    MEMVIEWPLUG_InjDll.name = "ScyllaHideCE Inject DLL";
    MEMVIEWPLUG_InjDll.callbackroutine = MemViewPlug_InjDll;
    //MEMVIEWPLUG_InjDll.shortcut = "Ctrl+Q";
    memorybrowserpluginid = Exported.RegisterFunction(pluginid, ptMemoryView, &MEMVIEWPLUG_InjDll);
    if (memorybrowserpluginid == -1)
    {
        Exported.ShowMessage("Failure to register the memoryview plugin");
        return FALSE;
    }

    MEMVIEWPLUG_attOrStrt.name = "ScyllaHideCE mode:   *Attach*";
    MEMVIEWPLUG_attOrStrt.callbackroutine = MemViewPlug_attOrOpn;
    //MEMVIEWPLUG_attOrStrt.shortcut = "Ctrl+Q";
    memorybrowserpluginid = Exported.RegisterFunction(pluginid, ptMemoryView, &MEMVIEWPLUG_attOrStrt);
    if (memorybrowserpluginid == -1)
    {
        Exported.ShowMessage("Failure to register the memoryview plugin");
        return FALSE;
    }

    //On Debug event plugin	
    DEBUGEVENTPLUGIN.callbackroutine = debugeventplugin;
    debugpluginID = Exported.RegisterFunction(pluginid, ptOnDebugEvent, &DEBUGEVENTPLUGIN);
    if (debugpluginID == -1)
    {
        Exported.ShowMessage("Failure to register the ondebugevent plugin");
        return FALSE;
    }

    //adding an item to context menu
    
    //DISASSEMBLERCONTEXT.name = "ScyllaHideCE options";
    //DISASSEMBLERCONTEXT.callbackroutine = disassemblercontext;
    //DISASSEMBLERCONTEXT.callbackroutineOnPopup = disassemblercontextPopup; // when is being added
    //disasmbCtxPluginID = Exported.RegisterFunction(pluginid, ptDisassemblerContext, &DISASSEMBLERCONTEXT);
    //if (disasmbCtxPluginID == -1)
    //{
    //    Exported.ShowMessage((char*)"Failure to register the disassemblercontext plugin");
    //    return FALSE;
    //}

    return TRUE;
}


BOOL __stdcall CEPlugin_DisablePlugin(void)
{
    return TRUE;
}



BOOL APIENTRY DllMain(HANDLE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        hinst = (HINSTANCE)hModule;

        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}
