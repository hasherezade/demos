#pragma once
#include <wchar.h>
#include "ntddk.h"

PVOID map_buffer_into_process(HANDLE hProcess, LPBYTE buffer, SIZE_T buffer_size)
{
    HANDLE hSection = NULL;
    OBJECT_ATTRIBUTES hAttributes;
    memset(&hAttributes, 0, sizeof(OBJECT_ATTRIBUTES));

    LARGE_INTEGER maxSize;
    maxSize.HighPart = 0;
    maxSize.LowPart = buffer_size;
    NTSTATUS status = NULL;
    if ((status = ZwCreateSection( &hSection, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_READWRITE, SEC_COMMIT, NULL)) != STATUS_SUCCESS)
    {
        printf("[ERROR] ZwCreateSection failed, status : %x\n", status);
        return NULL;
    }
    printf("Section handle: %x\n", hSection);

    PVOID sectionBaseAddress = NULL;
    SIZE_T viewSize = 0;
    SECTION_INHERIT inheritDisposition = ViewShare; //VIEW_SHARE

    // map the section in context of current process:
    if ((status = NtMapViewOfSection(hSection, GetCurrentProcess(), &sectionBaseAddress, NULL, NULL, NULL, &viewSize, inheritDisposition, NULL, PAGE_READWRITE)) != STATUS_SUCCESS)
    {
        printf("[ERROR] NtMapViewOfSection failed, status : %x\n", status);
        return NULL;
    }
    printf("Section BaseAddress: %p\n", sectionBaseAddress);

    memcpy (sectionBaseAddress, buffer, buffer_size);
    printf("Buffer copied!\n");

    //map the new section into context of opened process
    PVOID sectionBaseAddress2 = NULL;
    if ((status = NtMapViewOfSection(hSection, hProcess, &sectionBaseAddress2, NULL, NULL, NULL, &viewSize, ViewShare, NULL, PAGE_READWRITE)) != STATUS_SUCCESS)
    {
        printf("[ERROR] NtMapViewOfSection failed, status : %x\n", status);
        return NULL;
    }

    //unmap from the context of current process
    ZwUnmapViewOfSection(GetCurrentProcess(), sectionBaseAddress);
    ZwClose(hSection);

    printf("Section mapped at address: %p\n", sectionBaseAddress2);
    return sectionBaseAddress2;
}

HANDLE inject_with_loadlibrary(HANDLE hProcess, WCHAR *inject_path)
{
    SIZE_T inject_path_size = wcslen(inject_path) * sizeof(WCHAR);
    //we need to write the full path of the DLL into the remote process:
    PVOID remote_ptr = map_buffer_into_process(hProcess, (BYTE*)inject_path, inject_path_size);
    printf("Path writen to: %p\n", remote_ptr);

    HMODULE hModule = GetModuleHandle(L"kernel32.dll");
    if (!hModule) return NULL;

    FARPROC hLoadLib = GetProcAddress(hModule, "LoadLibraryW");
    if (!hLoadLib) return NULL;

    // Inject to the remote process:
    return CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hLoadLib, remote_ptr, NULL, NULL);
}