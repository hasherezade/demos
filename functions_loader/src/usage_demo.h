#pragma once

#include <Windows.h>

//Define the function prototype
typedef HMODULE (WINAPI* load_lib) (
    _In_ LPCSTR lpLibFileName
    );

typedef int (WINAPI *msg_box_w) (
    _In_opt_ HWND hWnd,
    _In_opt_ LPWSTR lpText,
    _In_opt_ LPWSTR lpCaption,
    _In_ UINT uType);

bool load_and_popup()
{
    LPVOID base = get_module_base(L"kernel32.dll");
    if (!base) {
        printf("loading kernel32.dll failed\n");
        return false;
    }
    load_lib load_lib_ptr = NULL;
    if (!(load_lib_ptr = (load_lib)get_exported_func((HMODULE) base, "LoadLibraryA"))) {
        printf("loading LoadLibraryA failed\n");
        return false;
    }

    HMODULE user32_ptr = (HMODULE)load_lib_ptr("user32.dll");
    if (!user32_ptr) {
        printf("loading user32.dll failed\n");
        return false;
    }

    msg_box_w msg_box_ptr = (msg_box_w)get_exported_func(user32_ptr, "MessageBoxW");
    if (msg_box_ptr == NULL) {
        printf("loading MessageBoxW failed\n");
        return false;
    }
    msg_box_ptr(NULL,  L"Demo works! Success!\nDemo dzia³a! Uda³o siê!", L"It works!", MB_OK);
    return true;
}