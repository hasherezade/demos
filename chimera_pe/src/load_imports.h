#pragma once
#include <Windows.h>
#include <stdio.h>

#include "pe_hdrs_helper.h"
#define SUPPORTED_LIB_NAME "kernel32.dll"

// warning! only functions from Kernel32.dll are supported
// the reason is they are loaded at the same address in all the modules

bool is_name(LPSTR lib_name, LPSTR supported_lib)
{
    SIZE_T kernel_name_len = strlen(supported_lib);

    size_t lib_name_len = strlen(lib_name);

    for (size_t i = 0; i < kernel_name_len && i < lib_name_len; i++) {
        CHAR c = tolower(lib_name[i]);
        if (c != supported_lib[i]) return false;
    }
    return true;
}

bool is_supported(LPSTR lib_name)
{
    if (is_name(lib_name, SUPPORTED_LIB_NAME)) {
        return true;
    }
    return false;
}

bool write_handle_b32(LPCSTR lib_name, DWORD call_via, LPSTR func_name, LPVOID modulePtr)
{
    HMODULE hBase = LoadLibraryA(lib_name);
    if (hBase == NULL) return false;

    FARPROC hProc = GetProcAddress(hBase, func_name);
    LPVOID call_via_ptr = (LPVOID)((DWORD)modulePtr + call_via);
    memcpy(call_via_ptr, &hProc, sizeof(DWORD));
    printf("proc addr: %p -> %p\n", hProc, call_via_ptr);
    return true;
}

bool solve_imported_funcs_b32(LPCSTR lib_name, DWORD call_via, DWORD thunk_addr, LPVOID modulePtr)
{
    do {
        LPVOID call_via_ptr = (LPVOID)((DWORD)modulePtr + call_via);
        if (call_via_ptr == NULL) break;

        LPVOID thunk_ptr = (LPVOID)((DWORD)modulePtr + thunk_addr);
        if (thunk_ptr == NULL) break;

        DWORD *thunk_val = (DWORD*)thunk_ptr;
        DWORD *call_via_val = (DWORD*)call_via_ptr;
        if (*call_via_val == 0) {
            //nothing to fill, probably the last record
            return true;
        }

        if (*thunk_val != *call_via_val) {
            //those two values are supposed to be the same before the file have imports filled
            //so, if they are different it means the handle is already filled
            printf("Import already filled\n");
        } else {
            //fill it:
            IMAGE_THUNK_DATA32* desc = (IMAGE_THUNK_DATA32*) thunk_ptr;
            if (desc->u1.Function == NULL) break;

            PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME) ((DWORD)modulePtr + desc->u1.AddressOfData);
            if (desc->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                printf("Imports by ordinals are not supported!\n");
                return false;
            }
            LPSTR func_name = by_name->Name;
            printf("name: %s\n", func_name);
            if (!write_handle_b32(lib_name, call_via, func_name, modulePtr)) {
                printf("Could not load the handle!\n");
                return false;
            }
        }
        call_via += sizeof(DWORD);
        thunk_addr += sizeof(DWORD);
    } while (true);
    return true;
}

//fills handles of mapped pe file
bool apply_imports(PVOID modulePtr)
{
    IMAGE_DATA_DIRECTORY *importsDir = get_pe_directory(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importsDir == NULL) return false;

    DWORD maxSize = importsDir->Size;
    DWORD parsedSize = 0;

    DWORD impAddr = importsDir->VirtualAddress;
    IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
    printf("---IMP---\n");
    while (parsedSize < maxSize) {
        lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR) modulePtr);
        parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR);

        if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == 0) {
            break;
        }

        printf("Imported Lib: %x : %x : %x\n", lib_desc->FirstThunk, lib_desc->OriginalFirstThunk, lib_desc->Name);
        LPSTR lib_name = (LPSTR)((DWORD)modulePtr + lib_desc->Name);
        printf("name: %s\n", lib_name);
        if (!is_supported(lib_name)) {
            printf("NOT SUPPORTED: for this method to work, EXE cannot have other imports than kernel32.dll or user32.dll!\n");
            return false;
        }

        DWORD call_via = lib_desc->FirstThunk;
        DWORD thunk_addr = lib_desc->OriginalFirstThunk ? lib_desc->OriginalFirstThunk : lib_desc->FirstThunk;
        if (thunk_addr == 0) break;

        solve_imported_funcs_b32(lib_name, call_via, thunk_addr, modulePtr);
    }
    printf("Imports ok!\n");
    printf("---------\n");
    return true;
}