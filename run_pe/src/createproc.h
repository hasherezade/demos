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
    ExpandEnvironmentStrings(L"%SystemRoot%\\system32\\calc.exe", lpwOutPath, szOutPath);
    printf("%S\n", lpwOutPath );
    return true;
}

bool get_explorer_path(LPWSTR lpwOutPath, DWORD szOutPath)
{
    ExpandEnvironmentStrings(L"%windir%\\explorer.exe", lpwOutPath, szOutPath);
    printf("%S\n", lpwOutPath );
    return true;
}


bool create_new_process1(IN LPWSTR path, OUT PROCESS_INFORMATION &pi)
{
    STARTUPINFO si;
    memset(&si, 0, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    memset(&pi, 0, sizeof(PROCESS_INFORMATION));

    if (!CreateProcess(
            NULL,
            path,
            NULL, //lpProcessAttributes
            NULL, //lpThreadAttributes
            NULL, //bInheritHandles
            CREATE_SUSPENDED, //dwCreationFlags
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
