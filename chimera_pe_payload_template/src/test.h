#pragma once

#include <Shlwapi.h>
#include <stdio.h>

#pragma comment(lib, "Shlwapi.lib")

bool get_notepad_path(LPWSTR lpwOutPath, DWORD szOutPath)
{
    ExpandEnvironmentStrings(L"%windir%\\notepad.exe", lpwOutPath, szOutPath);
    printf("%S\n", lpwOutPath );
    return true;
}

bool show_test_file()
{
    DWORD dwRetVal = 0;
    WCHAR lpTempPathBuffer[MAX_PATH];
    WCHAR filename[MAX_PATH];

    dwRetVal = GetTempPath(MAX_PATH, lpTempPathBuffer);
    if (dwRetVal > MAX_PATH || (dwRetVal == 0)) {
        return false;
    }
    PathCombine(filename, lpTempPathBuffer, L"hello_world.txt");
    printf("%S\n", filename);
    
    HANDLE hFile = CreateFile(filename, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    char data_buf[] = "Fine, everything works :)"; 
    DWORD writen = 0;
    BOOL isOk = WriteFile(hFile, data_buf, strlen(data_buf), &writen, NULL);
    CloseHandle(hFile);
    if (!isOk) return false;

    WCHAR editor_path[MAX_PATH];
    isOk = get_notepad_path(editor_path, MAX_PATH);
    if (!isOk) return false;
    ShellExecute(NULL, L"open", editor_path, filename, lpTempPathBuffer, SW_SHOWNORMAL);

    return true;
}

bool deploy_test()
{
    show_test_file();

    while (true) {
        MessageBoxA(NULL, "Hello! You just deployed a ChimeraPE! It works :D","Chimera Payload Template", MB_OK);
        Sleep(5000);
    }
}