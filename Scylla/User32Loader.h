#pragma once

#include <Windows.h>
#include <string>
#include <map>
#include <vector>

namespace scl
{
	class User32Loader
	{
	public:
		User32Loader();
		~User32Loader();

		bool FindSyscalls(const std::vector<std::string>& syscallNames);

		ULONG_PTR GetUserSyscallVa(const std::string& functionName) const { return FunctionNamesAndVas.at(functionName); }
		LONG GetUserSyscallIndex(const std::string& functionName) const;

	private:
		ULONG_PTR FindSyscallByIndex(LONG win32kSyscallIndex) const;

		const USHORT OsBuildNumber;
		const bool NativeX86;
		const PUCHAR Win32kUserDll; // win32u.dll if OsBuildNumber >= 14393, user32.dll otherwise

		std::map<std::string, ULONG_PTR> FunctionNamesAndVas;
	};
}
