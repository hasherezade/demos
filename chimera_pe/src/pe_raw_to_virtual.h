#pragma once

#include <windows.h>
#include <stdio.h>

#include "pe_hdrs_helper.h"

// Map raw PE into virtual memory of remote process
bool copy_pe_to_virtual_r(BYTE* payload, SIZE_T payload_size, LPVOID baseAddress, HANDLE hProcess)
{
    if (payload == NULL) return false;

    IMAGE_NT_HEADERS32* payload_nt_hdr = get_nt_hrds32(payload);
    if (payload_nt_hdr == NULL) {
        printf("Invalid payload: %p\n", payload);
        return false;
    }

    SIZE_T written = 0;

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
    secptr = LPVOID((ULONGLONG) secptr + kOptHdrSize);

    printf("Coping sections remotely:\n");
    for (WORD i = 0; i < payload_nt_hdr->FileHeader.NumberOfSections; i++) {
       PIMAGE_SECTION_HEADER next_sec = (PIMAGE_SECTION_HEADER)((ULONGLONG)secptr + (IMAGE_SIZEOF_SECTION_HEADER * i));

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

// Map raw PE into virtual memory of local process:
bool copy_pe_to_virtual_l(BYTE* payload, SIZE_T payload_size, LPVOID baseAddress)
{
    if (payload == NULL) return false;

    IMAGE_NT_HEADERS32* payload_nt_hdr = get_nt_hrds32(payload);
    if (payload_nt_hdr == NULL) {
        printf("Invalid payload: %p\n", payload);
        return false;
    }
    //copy payload's headers:
    const DWORD kHdrsSize = payload_nt_hdr->OptionalHeader.SizeOfHeaders;
    memcpy(baseAddress, payload, kHdrsSize);

    LPVOID secptr = &(payload_nt_hdr->OptionalHeader);
    const DWORD kOptHdrSize = payload_nt_hdr->FileHeader.SizeOfOptionalHeader;

    //copy all the sections, one by one:
    secptr = LPVOID((ULONGLONG) secptr + kOptHdrSize);

    printf("Coping sections locally:\n");
    for (WORD i = 0; i < payload_nt_hdr->FileHeader.NumberOfSections; i++) {
       PIMAGE_SECTION_HEADER next_sec = (PIMAGE_SECTION_HEADER)((ULONGLONG)secptr + (IMAGE_SIZEOF_SECTION_HEADER * i));

       LPVOID section_place = (BYTE*) baseAddress + next_sec->VirtualAddress;
       LPVOID section_raw_ptr = payload + next_sec->PointerToRawData;
       memcpy(section_place, section_raw_ptr, next_sec->SizeOfRawData);
       printf("[+] %s to: %p\n", next_sec->Name, section_place);
    }
    return true;
}
