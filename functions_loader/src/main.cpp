#include <windows.h>
#include <stdio.h>
#include "peb_lookup.h"
#include "exports_lookup.h"


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

int main(int argc, char *argv[])
{
    BYTE* res_data = NULL;
    SIZE_T res_size = 0;

    LPVOID base = test_fetching_module(L"kernel32.dll");
    if (!base) {
        system("pause");
        return -1;
    }

    if (!test_fetching_func((HMODULE) base, "LoadLibraryA")) {
        system("pause");
        return -1;
    }
    if (!test_fetching_func((HMODULE) base, "GetProcAddress")) {
        system("pause");
        return -1;
    }
    if (!test_fetching_func((HMODULE) base, "NeedCurrentDirectoryForExePathW")) {
        system("pause");
        return -1;
    }
    printf("All tests passed!\n");
    system("pause");
    return 0;
}
