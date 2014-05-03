#include "UpdateCheck.h"
#include <WinInet.h>
#include <string>
#include "..\ScyllaHideOlly2Plugin\ScyllaHideVersion.h"

bool isNewVersionAvailable()
{
    char buf[1024] = {0};
    DWORD dwBytesRead=0;
	HINTERNET hi=0, hCon=0;
	bool ret=0;

	hi = InternetOpenW(L"ScyllaHide Update Checker", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if(hi)
	{
		WCHAR szHead[] = L"Accept: */*\r\n\r\n";
		hCon = InternetOpenUrlW(hi, UPDATE_CHECK_URL, szHead, (DWORD)wcslen(szHead), INTERNET_FLAG_PRAGMA_NOCACHE, 0);
		if(hCon)
		{
			if(InternetReadFile(hCon, buf, sizeof(buf)-5, &dwBytesRead))
			{
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
						ret = true;
					}
					else
					{
						if (minor > SCYLLA_HIDE_MINOR_VERSION)
						{
							ret = true;
						}
					}
				}
			}
			else
			{
				MessageBoxA(0, "InternetReadFile failed", "ERROR", MB_ICONERROR);
			}
		}
		else
		{
			MessageBoxA(0, "InternetOpenUrlW failed", "ERROR", MB_ICONERROR);
		}
	}
	else
	{
		MessageBoxA(0, "InternetOpenW failed", "ERROR", MB_ICONERROR);
	}

	if(hi)
		InternetCloseHandle(hi);
	if(hCon)
		InternetCloseHandle(hCon);

	return ret;
}