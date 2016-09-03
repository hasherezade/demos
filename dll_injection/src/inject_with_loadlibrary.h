#pragma once
#include <wchar.h>
#include "ntddk.h"

#include "map_buffer_into_process.h"

HANDLE inject_with_loadlibrary(HANDLE hProcess, WCHAR *inject_path)
{
    SIZE_T inject_path_size = wcslen(inject_path) * sizeof(WCHAR);
    //we need to write the full path of the DLL into the remote process:

    PVOID remote_ptr = map_buffer_into_process1(hProcess, (BYTE*)inject_path, inject_path_size, PAGE_READWRITE);
    printf("Path writen to: %p\n", remote_ptr);

    HMODULE hModule = GetModuleHandle(L"kernel32.dll");
    if (!hModule) return NULL;

    FARPROC hLoadLib = GetProcAddress(hModule, "LoadLibraryW");
    if (!hLoadLib) return NULL;

    // Inject to the remote process:
    return CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hLoadLib, remote_ptr, NULL, NULL);
}