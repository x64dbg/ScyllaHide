#include "UpdateCheck.h"
#include <WinInet.h>
#include <string>
#include "..\ScyllaHideOlly2Plugin\ScyllaHideVersion.h"

bool isNewVersionAvailable()
{
    char buf[1024] = {0};
    DWORD dwBytesRead;

	HINTERNET hi = InternetOpenW(L"ScyllaHide Update Checker", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if(!hi)
	{
		MessageBoxA(0, "InternetOpenW failed", "ERROR", MB_ICONERROR);
		return false;
	}

    WCHAR szHead[] = L"Accept: */*\r\n\r\n";
	HINTERNET hCon = InternetOpenUrlW(hi, UPDATE_CHECK_URL, szHead, (DWORD)wcslen(szHead), INTERNET_FLAG_PRAGMA_NOCACHE, 0);
	if(!hCon)
	{
		MessageBoxA(0, "InternetOpenUrlW failed", "ERROR", MB_ICONERROR);
		return false;
	}

    if(!InternetReadFile(hCon, buf, sizeof(buf), &dwBytesRead))
	{
		MessageBoxA(0, "InternetReadFile failed", "ERROR", MB_ICONERROR);
		return false;
	}


    //compare the versions e.g. 0.7 1.0 0.5.b (lexicographical cmp might not work)

	char * temp = strchr(buf, '.');
	if (temp)
	{
		*temp = 0;
		temp++;

		int major = strtoul(buf, 0, 10);
		int minor = strtoul(temp, 0, 10);

		if (major > SCYLLA_HIDE_MAJOR_VERSION)
		{
			return true;
		}
		else
		{
			if (minor > SCYLLA_HIDE_MINOR_VERSION)
			{
				return true;
			}
		}
	}

    return false;
}