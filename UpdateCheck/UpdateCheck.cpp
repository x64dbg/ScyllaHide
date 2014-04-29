#include "UpdateCheck.h"
#include <WinInet.h>
#include <string>
#include "..\ScyllaHideOlly2Plugin\ScyllaHideVersion.h"

bool isNewVersionAvailable()
{
    char buf[1024] = {""};
    DWORD dwBytesRead;

    HINTERNET hi = InternetOpen(L"ScyllaHide Update Checker", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if(!hi) return false;

    WCHAR szHead[] = L"Accept: */*\r\n\r\n";
    HINTERNET hCon = InternetOpenUrlW(hi, UPDATE_CHECK_URL, szHead, wcslen(szHead), INTERNET_FLAG_DONT_CACHE, 0);
    if(!hCon) return false;

    if(!InternetReadFile(hCon, buf, 1024, &dwBytesRead)) return false;

    //compare the versions e.g. 0.7 1.0 0.5.b (lexicographical cmp might not work)
    //first compare major version
    int indexLatest = (int)(strstr(buf, ".")-buf);
    char majorLatest[3] = {""};
    strncpy_s(majorLatest, buf, indexLatest);

    if((int)*majorLatest > (int)*STR_HELPERA(SCYLLA_HIDE_MAJOR_VERSION)) return true;

    //next compare minor
    char* tmp = strstr(buf, ".");
    tmp+=1;
    indexLatest = (int)(strstr(tmp, ".")-tmp);
    char minorLatest[3] = {""};
    strncpy_s(minorLatest, tmp, indexLatest);

    if( (int)*minorLatest > (int)*STR_HELPERA(SCYLLA_HIDE_MINOR_VERSION))  return true;

    //finally compare patch level

    return false;
}