#include "User32Loader.h"
#include "Win32kSyscalls.h"
#include "Scylla/OsInfo.h"
#include "Scylla/Logger.h"

extern scl::Logger g_log;

scl::User32Loader::User32Loader() :
	OsBuildNumber(NtCurrentPeb()->OSBuildNumber),
	NativeX86(!scl::IsWindows64() && !scl::IsWow64Process(NtCurrentProcess)),
	Win32kUserDll((PUCHAR)LoadLibraryExW(OsBuildNumber >= 14393 ? L"win32u.dll" : L"user32.dll",
		nullptr, DONT_RESOLVE_DLL_REFERENCES | LOAD_IGNORE_CODE_AUTHZ_LEVEL |
		(OsBuildNumber >= 6002 ? LOAD_LIBRARY_SEARCH_SYSTEM32 : 0)))
{
}

scl::User32Loader::~User32Loader()
{
	if (Win32kUserDll != nullptr)
		FreeLibrary((HMODULE)Win32kUserDll);
}

// Finds the requested user32/win32u syscalls by name for later retrieval with GetUserSyscallVa
bool scl::User32Loader::FindSyscalls(const std::vector<std::string>& syscallNames)
{
	if (Win32kUserDll == nullptr) // Failed to load user32.dll or win32u.dll
		return false;
	if (OsBuildNumber < 2600) // Unsupported or unknown OS
		return false;

	if (OsBuildNumber >= 14393)
	{
		// On >= 10.0.14393.0 we can simply get the VAs from win32u.dll
		for (const auto& syscallName : syscallNames)
		{
			const ULONG_PTR syscallAddress = (ULONG_PTR)GetProcAddress((HMODULE)Win32kUserDll, syscallName.c_str());
			if (syscallAddress == 0)
				return false;
			FunctionNamesAndVas[syscallName] = syscallAddress;
		}
		return true;
	}

	// OS is < 14393. Get the syscall indices of the functions that we want the VAs of
	std::map<std::string, ULONG_PTR> functionNamesAndSyscallNums(FunctionNamesAndVas);
	for (const auto& syscallName : syscallNames)
	{
		const LONG syscallNum = GetUserSyscallIndex(syscallName);
		if (syscallNum == -1)
			return false;
		functionNamesAndSyscallNums[syscallName] = (ULONG_PTR)syscallNum;
	}

	// Find the VAs of the functions we want
	for (const auto& function : functionNamesAndSyscallNums)
	{
		const std::string syscallName = function.first;
		const ULONG_PTR syscallAddress = FindSyscallByIndex((ULONG)function.second);
		if (syscallAddress != 0)
		{
			FunctionNamesAndVas[syscallName] = syscallAddress;
		}
		else
		{
			g_log.LogError(L"Address of syscall %hs with index %u not found",
				syscallName.c_str(), (ULONG)functionNamesAndSyscallNums[syscallName]);
			return false;
		}
	}

	// Sanity check the NtUserBlockInput VA as this is an exported syscall
	const ULONG_PTR BlockInputVa = (ULONG_PTR)GetProcAddress((HMODULE)Win32kUserDll, "BlockInput");
	if (BlockInputVa == 0)
		return false;
	const bool check = GetUserSyscallVa("NtUserBlockInput") == BlockInputVa;
	if (!check)
		g_log.LogError(L"GetUserSyscallVa returned incorrect address 0x%p (expected 0x%p)!", GetUserSyscallVa("NtUserBlockInput"), BlockInputVa);
	
	return check;
}

// Returns the win32k syscall number for a function name
LONG scl::User32Loader::GetUserSyscallIndex(const std::string& functionName) const
{
	if (OsBuildNumber >= 14393)
	{
		const PUCHAR syscallAddress = (PUCHAR)GetProcAddress((HMODULE)Win32kUserDll, functionName.c_str());
		if (syscallAddress == nullptr)
			return -1;
		for (PUCHAR address = syscallAddress; address < syscallAddress + 16; ++address)
		{
			if (address[0] == 0xB8 && address[1] != 0xD1)
				return *(PLONG)(address + 1) & 0xFFFF;
		}
		return -1;
	}

	ANSI_STRING searchFunctionName;
	RtlInitAnsiString(&searchFunctionName, (PSTR)functionName.c_str());
	for (ULONG i = 0; i < ARRAYSIZE(Win32kSyscalls); ++i)
	{
		ANSI_STRING tableFunctionName = Win32kSyscalls[i].Name.ToAnsiString();
		if (!RtlEqualString(&tableFunctionName, &searchFunctionName, TRUE))
			continue;
		return Win32kSyscalls[i].GetSyscallIndex(OsBuildNumber, NativeX86);
	}
	return -1;
}

// Scans user32.dll and returns the VA of the function that performs the syscall with the given index
ULONG_PTR scl::User32Loader::FindSyscallByIndex(LONG win32kSyscallIndex) const
{
	const PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(Win32kUserDll);
	const PIMAGE_SECTION_HEADER codeSection = IMAGE_FIRST_SECTION(NtHeaders);
	const PUCHAR start = Win32kUserDll + codeSection->VirtualAddress;
	const PUCHAR end = Win32kUserDll + codeSection->VirtualAddress + codeSection->SizeOfRawData - 16;

	// Find the syscall pattern for this OS + architecture
	for (PUCHAR address = start; address < end; ++address)
	{
		if (address[0] != 0xB8 || (*(PLONG)(address + 1) & 0xFFFF) != win32kSyscallIndex) // mov eax, <syscall num>
			continue;

		bool isSyscall = false;
#ifdef _WIN64
		// For native x64 syscalls 'mov eax, <num>' is always preceded by 'mov r10, rcx'
		if (address[-3] == 0x4C && address[-2] == 0x8B && address[-1] == 0xD1)
		{
			isSyscall = true;
			address -= 3; // Backtrack to first mov
		}
#else
		if (NativeX86)
		{
			// Native x86, old style: mov edx, 7FFE0300h, call [edx]
			if (address[5] == 0xBA && address[6] == 0x00 && address[7] == 0x03 && address[8] == 0xFE &&
				address[9] == 0x7F && address[10] == 0xFF && address[11] == 0x12)
				isSyscall = true;
			// Win 8+ native x86: call leaf_sub, retn X. leaf_sub: mov edx, esp, sysenter, retn
			else if (address[5] == 0xE8 && address[9] == 0x00 && (address[10] == 0xC2 || address[10] == 0xC3))
			{
				ULONG i = 0;
				for ( ; i < 12; ++i)
				{
					if (address[11 + i] == 0x8B)
						break;
				}
				if (address[11 + i] == 0x8B && address[11 + i + 1] == 0xD4 && address[11 + i + 2] == 0x0F &&
					address[11 + i + 3] == 0x34 && address[11 + i + 4] == 0xC3)
					isSyscall = true;
			}
		}
		else
		{
			// Wow64, old style: lea edx, [esp+4] / mov ecx, XXXX, call fs:0C0h
			if ((address[5] == 0x8D || address[10] == 0x8D) && (address[5] == 0xB9 || address[9] == 0xB9))
				isSyscall = true;
			// Win 8/8.1 Wow64: call fs:0C0h
			else if (address[5] == 0x64 && address[6] == 0xFF && address[7] == 0x15 && address[8] == 0xC0 &&
				address[9] == 0x00 && address[10] == 0x00 && address[11] == 0x00)
				isSyscall = true;
			// Win 10 Wow64: mov edx, offset Wow64SystemServiceCall, call edx, retn
			else if (address[5] == 0xBA && address[10] == 0xFF && address[11] == 0xD2 && (address[12] == 0xC2 || address[12] == 0xC3))
				isSyscall = true;
		}
#endif
		if (isSyscall)
			return (ULONG_PTR)address;
	}
	return 0;
}
