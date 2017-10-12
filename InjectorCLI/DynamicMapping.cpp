#include "DynamicMapping.h"
#include <Psapi.h>
#include <ntdll/ntdll.h>

#pragma comment(lib, "psapi.lib")

LPVOID MapModuleToProcess(HANDLE hProcess, BYTE * dllMemory, bool wipeHeaders)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllMemory;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSecHeader = IMAGE_FIRST_SECTION(pNtHeader);

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pNtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        return nullptr;
    }

    IMAGE_DATA_DIRECTORY relocDir = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    bool relocatable = pNtHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    bool hasRelocDir = pNtHeader->FileHeader.NumberOfSections >= IMAGE_DIRECTORY_ENTRY_BASERELOC && relocDir.VirtualAddress > 0 && relocDir.Size > 0;
    if (!hasRelocDir && (pNtHeader->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)) // A relocation dir is optional, but it must not have been stripped
    {
        return nullptr;
    }

    ULONG_PTR headersBase = pNtHeader->OptionalHeader.ImageBase;
    LPVOID preferredBase = relocatable ? nullptr : (LPVOID)headersBase;
    LPVOID imageRemote = VirtualAllocEx(hProcess, preferredBase, pNtHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    LPVOID imageLocal = VirtualAlloc(nullptr, pNtHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (!imageLocal || !imageRemote)
    {
        return nullptr;
    }

    // Update the headers to the relocated image base
    if (relocatable && (ULONG_PTR)imageRemote != pNtHeader->OptionalHeader.ImageBase)
        pNtHeader->OptionalHeader.ImageBase = (ULONG_PTR)imageRemote;

    memcpy((LPVOID)imageLocal, (LPVOID)pDosHeader, pNtHeader->OptionalHeader.SizeOfHeaders);

    SIZE_T imageSize = pNtHeader->OptionalHeader.SizeOfImage;
    for (WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
    {
        if (hasRelocDir && i == pNtHeader->FileHeader.NumberOfSections - 1 &&
            pSecHeader->VirtualAddress == relocDir.VirtualAddress && (pSecHeader->Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
            imageSize = pSecHeader->VirtualAddress; // Limit the maximum VA to copy to the process to exclude .reloc if it is the last section

        memcpy((LPVOID)((DWORD_PTR)imageLocal + pSecHeader->VirtualAddress), (LPVOID)((DWORD_PTR)pDosHeader + pSecHeader->PointerToRawData), pSecHeader->SizeOfRawData);
        pSecHeader++;
    }

    if (hasRelocDir)
    {
        DWORD_PTR dwDelta = (DWORD_PTR)imageRemote - headersBase;
        DoBaseRelocation(
            (PIMAGE_BASE_RELOCATION)((DWORD_PTR)imageLocal + relocDir.VirtualAddress),
            (DWORD_PTR)imageLocal,
            dwDelta);
    }

    ResolveImports((PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)imageLocal + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress), (DWORD_PTR)imageLocal);

    SIZE_T skipBytes = wipeHeaders ? pNtHeader->OptionalHeader.SizeOfHeaders : 0;
    if (WriteProcessMemory(hProcess, (PVOID)((ULONG_PTR)imageRemote + skipBytes), (PVOID)((ULONG_PTR)imageLocal + skipBytes),
        imageSize - skipBytes, nullptr))
    {
        VirtualFree(imageLocal, 0, MEM_RELEASE);
    }
    else
    {
        VirtualFree(imageLocal, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, imageRemote, 0, MEM_RELEASE);
        imageRemote = nullptr;
    }
    return imageRemote;
}

bool ResolveImports(PIMAGE_IMPORT_DESCRIPTOR pImport, DWORD_PTR module)
{
    PIMAGE_THUNK_DATA thunkRef;
    PIMAGE_THUNK_DATA funcRef;

    while (pImport->FirstThunk)
    {
        char * moduleName = (char *)(module + pImport->Name);

        HMODULE hModule = GetModuleHandleA(moduleName);

        if (!hModule)
        {
            hModule = LoadLibraryA(moduleName);
            if (!hModule)
            {
                return false;
            }
        }

        funcRef = (PIMAGE_THUNK_DATA)(module + pImport->FirstThunk);
        if (pImport->OriginalFirstThunk)
        {
            thunkRef = (PIMAGE_THUNK_DATA)(module + pImport->OriginalFirstThunk);
        }
        else
        {
            thunkRef = (PIMAGE_THUNK_DATA)(module + pImport->FirstThunk);
        }

        while (thunkRef->u1.Function)
        {
            if (IMAGE_SNAP_BY_ORDINAL(thunkRef->u1.Function))
            {
                funcRef->u1.Function = (DWORD_PTR)GetProcAddress(hModule, (LPCSTR)IMAGE_ORDINAL(thunkRef->u1.Ordinal));
            }
            else
            {
                PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)(module + thunkRef->u1.AddressOfData);
                funcRef->u1.Function = (DWORD_PTR)GetProcAddress(hModule, (LPCSTR)thunkData->Name);
            }

            if (!funcRef->u1.Function)
            {
                MessageBoxA(0, "Function not resolved", moduleName, 0);
                return false;
            }

            thunkRef++;
            funcRef++;
        }

        pImport++;
    }

    return true;
}

void DoBaseRelocation(PIMAGE_BASE_RELOCATION relocation, DWORD_PTR memory, DWORD_PTR dwDelta)
{
    DWORD_PTR * patchAddress;
    WORD type, offset;

    while (relocation->VirtualAddress)
    {
        PBYTE dest = (PBYTE)(memory + relocation->VirtualAddress);
        DWORD count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD * relocInfo = (WORD *)((DWORD_PTR)relocation + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < count; i++)
        {
            type = relocInfo[i] >> 12;
            offset = relocInfo[i] & 0xfff;

            switch (type)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                break;
            case IMAGE_REL_BASED_HIGHLOW:
            case IMAGE_REL_BASED_DIR64:
                patchAddress = (DWORD_PTR *)(dest + offset);
                *patchAddress += dwDelta;
                break;
            default:
                break;
            }
        }

        relocation = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocation + relocation->SizeOfBlock);
    }
}

DWORD RVAToOffset(PIMAGE_NT_HEADERS pNtHdr, DWORD dwRVA)
{
    PIMAGE_SECTION_HEADER pSectionHdr = IMAGE_FIRST_SECTION(pNtHdr);

    for (WORD i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++)
    {
        if (pSectionHdr->VirtualAddress <= dwRVA)
        {
            if ((pSectionHdr->VirtualAddress + pSectionHdr->Misc.VirtualSize) > dwRVA)
            {
                dwRVA -= pSectionHdr->VirtualAddress;
                dwRVA += pSectionHdr->PointerToRawData;

                return (dwRVA);
            }

        }
        pSectionHdr++;
    }

    return (0);
}

DWORD GetDllFunctionAddressRVA(BYTE * dllMemory, LPCSTR apiName)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllMemory;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir;

    DWORD exportDirRVA = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportDirOffset = RVAToOffset(pNtHeader, exportDirRVA);

    pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)dllMemory + exportDirOffset);

    DWORD * addressOfFunctionsArray = (DWORD *)((DWORD)pExportDir->AddressOfFunctions - exportDirRVA + (DWORD_PTR)pExportDir);
    DWORD * addressOfNamesArray = (DWORD *)((DWORD)pExportDir->AddressOfNames - exportDirRVA + (DWORD_PTR)pExportDir);
    WORD * addressOfNameOrdinalsArray = (WORD *)((DWORD)pExportDir->AddressOfNameOrdinals - exportDirRVA + (DWORD_PTR)pExportDir);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++)
    {
        char * functionName = (char*)(addressOfNamesArray[i] - exportDirRVA + (DWORD_PTR)pExportDir);

        if (!_stricmp(functionName, apiName))
        {
            return addressOfFunctionsArray[addressOfNameOrdinalsArray[i]];
        }
    }

    return 0;
}

HMODULE GetModuleBaseRemote(HANDLE hProcess, const wchar_t* szDLLName)
{
    DWORD cbNeeded = 0;
    wchar_t szModuleName[MAX_PATH] = { 0 };
    if (EnumProcessModules(hProcess, 0, 0, &cbNeeded))
    {
        HMODULE* hMods = (HMODULE*)malloc(cbNeeded*sizeof(HMODULE));
        if (EnumProcessModules(hProcess, hMods, cbNeeded, &cbNeeded))
        {
            for (unsigned int i = 0; i < cbNeeded / sizeof(HMODULE); i++)
            {
                szModuleName[0] = 0;
                if (GetModuleFileNameExW(hProcess, hMods[i], szModuleName, _countof(szModuleName)))
                {
                    wchar_t* dllName = wcsrchr(szModuleName, L'\\');
                    if (dllName)
                    {
                        dllName++;
                        if (!_wcsicmp(dllName, szDLLName))
                        {
                            return hMods[i];
                        }
                    }
                }
            }
        }
        free(hMods);
    }
    return 0;
}

DWORD StartDllInitFunction(HANDLE hProcess, DWORD_PTR functionAddress, LPVOID imageBase)
{
    NTSTATUS ntStat = 0;
    DWORD dwExit = 0;
    HANDLE hThread = 0;
    t_NtCreateThreadEx _NtCreateThreadEx = (t_NtCreateThreadEx)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");


    //	if (_NtCreateThreadEx)
    //	{
    //#define THREAD_ALL_ACCESS_VISTA         (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
    //	0xFFFF)
    //		ntStat = _NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS_VISTA, 0, hProcess, (LPTHREAD_START_ROUTINE)functionAddress, imageBase, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, 0, 0, 0, 0);
    //	}
    //	else
    {
        hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)functionAddress, imageBase, CREATE_SUSPENDED, 0);
    }

    if (hThread)
    {
        ntStat = NtSetInformationThread(hThread, ThreadHideFromDebugger, 0, 0);

        //SkipThreadAttach(hProcess, hThread);

        ResumeThread(hThread);

        WaitForSingleObject(hThread, INFINITE);
        GetExitCodeThread(hThread, &dwExit);

        CloseHandle(hThread);
        return dwExit;
    }

    return -1;
}

bool SkipThreadAttach(HANDLE hProcess, HANDLE hThread)
{
    USHORT tebFlags = 0;
    THREAD_BASIC_INFORMATION tbi = { 0 };
    if (NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(THREAD_BASIC_INFORMATION), 0) >= 0)
    {
        DWORD_PTR tebAddress = (DWORD_PTR)tbi.TebBaseAddress;

        DWORD_PTR tebFlagAddress = tebAddress + TEB_OFFSET_SAME_TEB_FLAGS;

        if (ReadProcessMemory(hProcess, (void*)tebFlagAddress, &tebFlags, sizeof(USHORT), 0))
        {
            SameTebFlags * structFlags = (SameTebFlags *)&tebFlags;
            structFlags->DbgSkipThreadAttach = TRUE;
            return !!WriteProcessMemory(hProcess, (void*)tebFlagAddress, &tebFlags, sizeof(USHORT), 0);
        }
    }

    return false;
}

bool StartSystemBreakpointInjection(DWORD threadid, HANDLE hProcess, DWORD_PTR functionAddress, LPVOID imageBase)
{
    CONTEXT ctx = { 0 };
    BYTE injectStub[500] = { 0 };
    ctx.ContextFlags = CONTEXT_CONTROL;

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, threadid);
    //wsprintfA(text, "%X %X", hThread, threadi);
    //MessageBoxA(0,text,"StartSystemBreakpointInjection",0);

    if (hThread && (NtGetContextThread(hThread, &ctx) >= 0))
    {
        //wsprintfA(text, "%X", ctx.Eip);
        //MessageBoxA(0,text,"NtGetContextThread",0);

        LPVOID memory = VirtualAllocEx(hProcess, 0, GetInjectStubSize(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (memory)
        {
            //wsprintfA(text, "%X", memory);
            //MessageBoxA(0, text, text, 0);
#ifdef _WIN64 //x64
            PrepareInjectStub((DWORD_PTR)memory, (DWORD_PTR)imageBase, ctx.Rip, functionAddress, injectStub);
#else //x64
            PrepareInjectStub((DWORD_PTR)memory, (DWORD_PTR)imageBase, ctx.Eip, functionAddress, injectStub);
#endif //_WIN64
            if (WriteProcessMemory(hProcess, memory, injectStub, GetInjectStubSize(), 0))
            {
#ifdef _WIN64 //x64
                ctx.Rip = (DWORD_PTR)memory;
#else //x64
                ctx.Eip = (DWORD_PTR)memory;
#endif //_WIN64
                return (NtSetContextThread(hThread, &ctx) >= 0);
            }

        }
    }
    CloseHandle(hThread);
    return false;
}

#ifndef _WIN64
//32bit
BYTE pushad = 0x60;//PUSHAD
BYTE popad = 0x61;//POPAD
BYTE pushDword[] = { 0x68, 0x00, 0x00, 0x00, 0x00 };
BYTE callDword[] = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
BYTE jmpDword[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };

int GetInjectStubSize()
{
    return sizeof(pushDword) + sizeof(callDword) + sizeof(jmpDword) + 2;
}

void PrepareInjectStub(DWORD memoryAddress, DWORD dllImageBase, DWORD systemBreakpointContinue, DWORD dllInitAddress, BYTE * result)
{
    DWORD * temp = (DWORD *)&pushDword[1];
    *temp = dllImageBase;

    temp = (DWORD *)&callDword[1];
    *temp = (DWORD)(dllInitAddress - (memoryAddress + sizeof(pushDword) + 1) - 5);

    temp = (DWORD *)&jmpDword[1];
    *temp = (DWORD)(systemBreakpointContinue - (memoryAddress + sizeof(pushDword) + sizeof(callDword) + 2) - 5);

    result[0] = pushad;
    memcpy(result + 1, pushDword, sizeof(pushDword));
    memcpy(result + 1 + sizeof(pushDword), callDword, sizeof(callDword));
    memcpy(result + 1 + sizeof(pushDword) + sizeof(callDword), &popad, 1);
    memcpy(result + 1 + sizeof(pushDword) + sizeof(callDword) + 1, jmpDword, sizeof(jmpDword));

}
#else
//64bit
BYTE movRcx[] = { 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
BYTE callQword[] = { 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00 }; //dll init
BYTE jmpQword[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
BYTE addressTable[8 * 2] = { 0 };

int GetInjectStubSize()
{
    return sizeof(movRcx)+sizeof(callQword)+sizeof(jmpQword)+sizeof(addressTable);
}

void PrepareInjectStub(DWORD_PTR memoryAddress, DWORD_PTR dllImageBase, DWORD_PTR systemBreakpointContinue, DWORD_PTR dllInitAddress, BYTE * result)
{
    DWORD_PTR * temp = (DWORD_PTR *)&movRcx[2];
    *temp = dllImageBase;

    temp = (DWORD_PTR *)addressTable;
    *temp = dllInitAddress;
    temp++;
    *temp = systemBreakpointContinue;

    DWORD * tempDw = (DWORD*)&callQword[2];
    *tempDw = sizeof(jmpQword);

    tempDw = (DWORD*)&jmpQword[2];
    *tempDw = sizeof(DWORD_PTR);

    memcpy(result, movRcx, sizeof(movRcx));
    memcpy(result + sizeof(movRcx), callQword, sizeof(callQword));
    memcpy(result + sizeof(movRcx)+sizeof(callQword), jmpQword, sizeof(jmpQword));
    memcpy(result + sizeof(movRcx)+sizeof(callQword)+sizeof(jmpQword), addressTable, sizeof(addressTable));
}
#endif
