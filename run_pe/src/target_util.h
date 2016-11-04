#pragma once

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
#if defined(_WIN64)
    ExpandEnvironmentStrings(L"%SystemRoot%\\SysWoW64\\calc.exe", lpwOutPath, szOutPath);
#else
    ExpandEnvironmentStrings(L"%SystemRoot%\\system32\\calc.exe", lpwOutPath, szOutPath);
#endif
    printf("%S\n", lpwOutPath );
    return true;
}

bool get_svchost_path(LPWSTR lpwOutPath, DWORD szOutPath)
{
#if defined(_WIN64)
    ExpandEnvironmentStrings(L"%SystemRoot%\\SysWoW64\\svchost.exe", lpwOutPath, szOutPath);
#else
    ExpandEnvironmentStrings(L"%SystemRoot%\\system32\\svchost.exe", lpwOutPath, szOutPath);
#endif
    printf("%S\n", lpwOutPath );
    return true;
}

bool get_explorer_path(LPWSTR lpwOutPath, DWORD szOutPath)
{
    ExpandEnvironmentStrings(L"%windir%\\explorer.exe", lpwOutPath, szOutPath);
    printf("%S\n", lpwOutPath );
    return true;
}
