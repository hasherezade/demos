#pragma once
#include "kernel32_undoc.h"

bool get_default_browser(LPWSTR lpwOutPath, DWORD szOutPath)
{
    HKEY phkResult;
    DWORD iMaxLen = szOutPath;

    LSTATUS res = RegOpenKeyEx(HKEY_CLASSES_ROOT, L"HTTP\\shell\\open\\command", 0, 1u, &phkResult);
    if (res != ERROR_SUCCESS) {
        printf("[ERROR] Failed with value = %x\n", res);
        return false;
    }

    res = RegQueryValueEx(phkResult, NULL, NULL, NULL, (LPBYTE) lpwOutPath, (LPDWORD) &iMaxLen);
    if (res != ERROR_SUCCESS) {
        printf("[ERROR] Failed with value = %x\n", res);
        return false;
    }
    printf("%S\n", lpwOutPath );
    return true;
}

bool get_calc_path(LPWSTR lpwOutPath, DWORD szOutPath)
{
    ExpandEnvironmentStrings(L"%SystemRoot%\\system32\\calc.exe", lpwOutPath, szOutPath);
    printf("%S\n", lpwOutPath );
    return true;
}

bool create_new_process1(PROCESS_INFORMATION &pi)
{
    WCHAR lpwOutPath[MAX_PATH];
    get_default_browser(lpwOutPath, MAX_PATH);

    STARTUPINFO si;
    memset(&si, 0, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    memset(&pi, 0, sizeof(PROCESS_INFORMATION));

    if (!CreateProcess(
            NULL,
            lpwOutPath,
            NULL, //lpProcessAttributes
            NULL, //lpThreadAttributes
            NULL, //bInheritHandles
            DETACHED_PROCESS|CREATE_SUSPENDED|CREATE_NO_WINDOW, //dwCreationFlags
            NULL, //lpEnvironment 
            NULL, //lpCurrentDirectory
            &si, //lpStartupInfo
            &pi //lpProcessInformation
        ))
    {
        printf("[ERROR] CreateProcess failed, Error = %x\n", GetLastError());
        return false;
    }
    return true;
}

bool create_new_process2(PROCESS_INFORMATION &pi)
{
    WCHAR lpwOutPath[MAX_PATH];
    get_default_browser(lpwOutPath, MAX_PATH);

    STARTUPINFO si;
    memset(&si, 0, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    memset(&pi, 0, sizeof(PROCESS_INFORMATION));

    HANDLE hToken = NULL;
    HANDLE hNewToken = NULL;
    if (!CreateProcessInternalW (hToken,
            NULL, //lpApplicationName
            (LPWSTR) lpwOutPath, //lpCommandLine
            NULL, //lpProcessAttributes
            NULL, //lpThreadAttributes
            NULL, //bInheritHandles
            CREATE_SUSPENDED|DETACHED_PROCESS|CREATE_NO_WINDOW, //dwCreationFlags
            NULL, //lpEnvironment 
            NULL, //lpCurrentDirectory
            &si, //lpStartupInfo
            &pi, //lpProcessInformation
            &hNewToken
        ))
    {
        printf("[ERROR] CreateProcessInternalW failed, Error = %x\n", GetLastError());
        return false;
    }
    return true;
}
