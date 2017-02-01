#pragma once
#include <Windows.h>
#include <stdio.h>

#include "pe_hdrs_helper.h"

//define functions prototypes
typedef HMODULE (WINAPI *load_lib) (
    _In_ LPCSTR lpLibFileName
    );

typedef BOOL (WINAPI* virtual_protect) (
    _In_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flNewProtect,
    _Out_ PDWORD lpflOldProtect
    );


typedef FARPROC (WINAPI* get_proc_addr) (
    _In_ HMODULE hModule,
    _In_ LPCSTR lpProcName
    );

//define handles:
HMODULE kernel32_base = NULL;
load_lib load_lib_ptr = NULL;
virtual_protect virtual_protect_ptr = NULL;
get_proc_addr get_proc_addr_ptr = NULL;

LPVOID get_module_bgn(BYTE *start)
{
    while (start != NULL) {
        IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER*) start;
        if (get_nt_hrds((BYTE*)idh) != NULL) return idh;
        start--;
    }
    return NULL;
}

bool init_functions()
{
    kernel32_base = GetModuleHandle(L"kernel32.dll");
    if (kernel32_base == NULL) return false;

    load_lib_ptr = (load_lib)GetProcAddress(kernel32_base, "LoadLibraryA");
    virtual_protect_ptr = (virtual_protect)GetProcAddress(kernel32_base, "VirtualProtect");
    get_proc_addr_ptr = (get_proc_addr)GetProcAddress(kernel32_base, "GetProcAddress");
    if (!load_lib_ptr || !virtual_protect_ptr || !get_proc_addr_ptr) {
        return false;
    }
    return true;
}

bool write_handle_b32(HMODULE hLib, DWORD call_via,  LPSTR func_name, LPVOID modulePtr)
{
    FARPROC hProc = (FARPROC)get_proc_addr_ptr(hLib, func_name);
    LPVOID call_via_ptr = (LPVOID)((ULONGLONG)modulePtr + call_via);
    DWORD oldProtect;

    virtual_protect_ptr((BYTE*)call_via_ptr, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(call_via_ptr, &hProc, sizeof(DWORD));
    virtual_protect_ptr((BYTE*)call_via_ptr, sizeof(DWORD), oldProtect, &oldProtect);
    printf("proc addr: %p -> %p\n", hProc, call_via_ptr);
    return true;
}

bool solve_imported_funcs_b32(LPSTR lib_name, DWORD call_via, DWORD thunk_addr, LPVOID modulePtr)
{
    // if handles to functions from user32.dll were filled by the loader
    // but in the target - user32.dll was not loaded - it will get loaded now
    // and handles will become valid:
    HMODULE hLib = load_lib_ptr(lib_name);
    if (hLib == NULL) return false;

    //for other unsolved libraries, handles must be retrieved and written:
    do {
        LPVOID call_via_ptr = (LPVOID)((ULONGLONG)modulePtr + call_via);
        if (call_via_ptr == NULL) break;

        LPVOID thunk_ptr = (LPVOID)((ULONGLONG)modulePtr + thunk_addr);
        if (thunk_ptr == NULL) break;

        DWORD *thunk_val = (DWORD*)thunk_ptr;
        DWORD *call_via_val = (DWORD*)call_via_ptr;
        if (*call_via_val == 0) {
            //nothing to fill, probably the last record
            return true;
        }

        //those two values are supposed to be the same before the file have imports filled
        //so, if they are different it means the handle is already filled
        if (*thunk_val == *call_via_val) {
            //fill it:
            IMAGE_THUNK_DATA32* desc = (IMAGE_THUNK_DATA32*) thunk_ptr;
            if (desc->u1.Function == NULL) break;

            PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME) ((ULONGLONG)modulePtr + desc->u1.AddressOfData);
            if (desc->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                //Imports by ordinals are not supported for now
                return false;
            }
            LPSTR func_name = by_name->Name;
            printf("name: %s\n", func_name);
            if (!write_handle_b32(hLib, call_via, func_name, modulePtr)) {
                //printf("Could not load the handle!\n");
                return false;
            }
        }
        call_via += sizeof(DWORD);
        thunk_addr += sizeof(DWORD);
    } while (true);
    return true;
}

//fills handles of mapped pe file
bool apply_imports32(LPVOID modulePtr=NULL)
{
    if (!modulePtr) {
        modulePtr = get_module_bgn((BYTE*)&apply_imports32);
        printf("Module Hndl: %p\n", modulePtr);
    }
    IMAGE_DATA_DIRECTORY *importsDir = get_pe_directory(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importsDir == NULL) return false;
    
    if (!init_functions()) return false;

    DWORD maxSize = importsDir->Size;
    DWORD parsedSize = 0;

    DWORD impAddr = importsDir->VirtualAddress;
    IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;

    while (parsedSize < maxSize) {
        lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR) modulePtr);
        parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR);

        if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == 0) {
            break;
        }

        printf("Imported Lib: %x : %x : %x\n", lib_desc->FirstThunk, lib_desc->OriginalFirstThunk, lib_desc->Name);
        LPSTR lib_name = (LPSTR)((ULONGLONG) modulePtr + lib_desc->Name);
        printf("name: %s\n", lib_name);

        DWORD call_via = lib_desc->FirstThunk;
        DWORD thunk_addr = lib_desc->OriginalFirstThunk ? lib_desc->OriginalFirstThunk : lib_desc->FirstThunk;
        if (thunk_addr == 0) break;

        solve_imported_funcs_b32(lib_name, call_via, thunk_addr, modulePtr);
    }
    return true;
}