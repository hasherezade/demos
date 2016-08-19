#pragma once
#include <stdio.h>
#include "ntddk.h"

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
    HANDLE threadHandle = NULL;
    //create a new thread for the injected code:
    if ((status = ZwCreateThreadEx(&threadHandle, 0x1FFFFF, NULL, hProcess, remote_shellcode_ptr, NULL, CREATE_SUSPENDED, 0, 0, 0, 0)) != STATUS_SUCCESS)
    {
        printf("[ERROR] ZwCreateThreadEx failed, status : %x\n", status);
        return false;
    }
    printf("Created Thread, id = %x\n", GetThreadId(threadHandle));
    printf("Resuming added thread...\n");
    ResumeThread(threadHandle); //injected code
    return true;
}
