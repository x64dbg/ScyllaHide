#pragma once
#include <Windows.h>

#define DEFAULT_PROFILE L"SCYLLA_HIDE"
#define INDEPENDENT_SECTION L"SETTINGS"
#define MAX_SECTION_NAME 256

BOOL FileExists(LPCWSTR szPath);
void CreateSettings();
void ReadSettings();
int ReadIniSettingsInt(const WCHAR * settingName, const WCHAR* inifile);
void ReadIniSettings(const WCHAR * settingName, const WCHAR* inifile, WCHAR* buf, int bufsz);
void ReadSettingsFromIni(const WCHAR * iniFile);
void CreateDummyUnicodeFile(const WCHAR * file);
bool WriteIniSettings(const WCHAR * settingName, const WCHAR * settingValue, const WCHAR* inifile);
bool WriteIniSettingsInt(const WCHAR * settingName, int settingValue, const WCHAR* inifile);
void CreateDefaultSettings(const WCHAR * iniFile);
void SaveSettings();
void SaveSettingsToIni(const WCHAR * iniFile);
void GetProfileNames(char* sectionNamesA);
void SetCurrentProfile(const WCHAR* profile);
void SetCurrentProfile(int index);
void SaveCurrentProfile(const WCHAR* profile);
void ReadCurrentProfile();
void GetPrivateProfileSectionNamesWithFilter();