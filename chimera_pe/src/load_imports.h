#pragma once
#include <Windows.h>
#include <stdio.h>

#include "pe_hdrs_helper.h"
#define SUPPORTED_LIB_NAME "kernel32.dll"

// warning! only functions from Kernel32.dll can be solved like this!
// the reason is kernel32 is guaranteed to be loaded at the same address in all the modules

bool is_kernel32(LPSTR lib_name)
{
    static CHAR kernel_name[] = SUPPORTED_LIB_NAME;
    static SIZE_T kernel_name_len = strlen(kernel_name);

    size_t lib_name_len = strlen(lib_name);

    for (size_t i = 0; i < kernel_name_len && i < lib_name_len; i++) {
        CHAR c = tolower(lib_name[i]);
        if (c != kernel_name[i]) return false;
    }
    return true;
}

bool write_handle_b32(DWORD call_via, LPSTR func_name, LPVOID modulePtr)
{
    static CHAR kernel_name[] = SUPPORTED_LIB_NAME;
    HMODULE hKernel = LoadLibraryA(kernel_name);
    if (hKernel == NULL) return false;

    FARPROC hProc = GetProcAddress(hKernel, func_name);
    LPVOID store_handle = (LPVOID)((DWORD)modulePtr + call_via);
    memcpy(store_handle, &hProc, sizeof(DWORD));
    printf("proc addr: %p -> %p\n", hProc, store_handle);
    return true;
}

bool solve_imported_funcs_b32(DWORD call_via, LPVOID modulePtr)
{
    do {
        LPVOID entryPtr = (LPVOID)((DWORD)modulePtr + call_via);
        if (entryPtr == NULL) break;

        IMAGE_THUNK_DATA32* desc = (IMAGE_THUNK_DATA32*) entryPtr;
        if (desc->u1.Function == NULL) break;

        PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME) ((DWORD)modulePtr + desc->u1.AddressOfData);
        if (desc->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
            printf("Imports by ordinals are not supported!\n");
            return false;
        }
        LPSTR func_name = by_name->Name;
        printf("name: %s\n", func_name);
        if (!write_handle_b32(call_via, func_name, modulePtr)) {
            printf("Could not load the handle!\n");
            return false;
        }
        call_via += sizeof(DWORD);
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
        if (!is_kernel32(lib_name)) {
            printf("NOT SUPPORTED: for this method to work, EXE cannot have other imports than kernel32.dll!\n");
            return false;
        }
        DWORD call_via = (lib_desc->FirstThunk != NULL) ? lib_desc->FirstThunk : lib_desc->OriginalFirstThunk;
        if (call_via == 0) break;

        solve_imported_funcs_b32(call_via, modulePtr);
    }
    printf("Imports ok!\n");
    printf("---------\n");
    return true;
}