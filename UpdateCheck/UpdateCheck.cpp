#include "UpdateCheck.h"
#include <UrlMon.h>
#include <WinInet.h>
#include <string>

bool isNewVersionAvailable(char* curVersion)
{
    WCHAR lpTempFileName[MAX_PATH];
    WCHAR lpTempPath[MAX_PATH];
    char buf[1024] = {""};
    DWORD dwBytesRead;
    DWORD ret;

    ret = GetTempPathW(MAX_PATH, lpTempPath);
    if(ret > MAX_PATH || (ret == 0)) return false;

    ret = GetTempFileNameW(lpTempPath, L"SCYLLAHIDE_", 0, lpTempFileName);
    if(ret == 0) return false;

    DeleteUrlCacheEntryW(UPDATE_CHECK_URL);

    HRESULT res = URLDownloadToFileW(NULL, UPDATE_CHECK_URL, lpTempFileName, 0, NULL);
    if(res != S_OK) return false;

    HANDLE hUpdateFile = CreateFileW(lpTempFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    ret = ReadFile(hUpdateFile, buf, 1024, &dwBytesRead, NULL);
    if(ret == 0) {
        CloseHandle(hUpdateFile);
        return false;
    }

    //compare the versions e.g. 0.7 1.0 0.5.b (lexicographical cmp might not work)
    //first compare major version
    int indexCur = (int)(strstr(curVersion, ".")-curVersion);
    char majorCur[3] = {""};
    strncpy_s(majorCur, curVersion, indexCur);

    int indexLatest = (int)(strstr(buf, ".")-buf);
    char majorLatest[3] = {""};
    strncpy_s(majorLatest, buf, indexLatest);

    if((int)*majorLatest > (int)*majorCur) return true;

    //next compare minor
    char* tmp = strstr(curVersion, ".");
    tmp+=1;
    indexCur = (int)(strstr(tmp, ".")-tmp);
    char minorCur[3] = {""};
    strncpy_s(minorCur, tmp, indexCur);

    tmp = strstr(buf, ".");
    tmp+=1;
    indexLatest = (int)(strstr(tmp, ".")-tmp);
    char minorLatest[3] = {""};
    strncpy_s(minorLatest, tmp, indexLatest);

    if( (int)*minorLatest > (int)*minorCur)  return true;

    //finally compare patch level

    return false;
}