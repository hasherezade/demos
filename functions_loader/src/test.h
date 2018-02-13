#pragma once

#include <Windows.h>

//tries to fetch module base via PEB,
//compares the result with output of analogical function GetModuleHandleW
LPVOID test_fetching_module(LPWSTR libName)
{
    LPVOID base = get_module_base(libName);
    if (base == GetModuleHandleW(libName)) {
        printf("[OK] %S : %p\n", libName, base);
        return base;
    }
    printf("[FAILED] %S\n", libName);
    return NULL;
}

//tries to fetch module base via export table,
//compares the result with output of analogical function GetProcAddress
LPVOID test_fetching_func(HMODULE hModule, LPSTR funcName)
{
    LPVOID hFunc = get_exported_func(hModule, funcName);
    if (hFunc == GetProcAddress((HMODULE)hModule, funcName)) {
        printf("[OK] %s : %p\n", funcName, hFunc);
        return hFunc;
    }
    printf("[FAILED] %s\n", funcName);
    return NULL;
}

bool test_loading()
{
    LPVOID base = test_fetching_module(L"kernel32.dll");
    if (!base) {
        return false;
    }

    if (!test_fetching_func((HMODULE) base, "LoadLibraryA")) {
        return false;
    }
    if (!test_fetching_func((HMODULE) base, "GetProcAddress")) {
        return false;
    }
    if (!test_fetching_func((HMODULE) base, "NeedCurrentDirectoryForExePathW")) {
        return false;
    }
    printf("All tests passed!\n");
    return true;
}
