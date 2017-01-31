#pragma once

#include <Windows.h>
#include "ntddk.h"

//here we don't want to use any functions imported form extenal modules

typedef struct _LDR_MODULE { 
    LIST_ENTRY  InLoadOrderModuleList;//   +0x00 
    LIST_ENTRY  InMemoryOrderModuleList;// +0x08   
    LIST_ENTRY  InInitializationOrderModuleList;// +0x10 
    void*   BaseAddress; // +0x18 
    void*   EntryPoint;  // +0x1c 
    ULONG   SizeOfImage; 
    LPWSTR  FullDllName; 
    LPWSTR  BaseDllName; 
    ULONG   Flags; 
    SHORT   LoadCount; 
    SHORT   TlsIndex; 
    HANDLE  SectionHandle; 
    ULONG   CheckSum; 
    ULONG   TimeDateStamp; 
} LDR_MODULE, *PLDR_MODULE;

inline PPEB get_peb()
{
    LPVOID PEB = NULL;
#if defined(_WIN64)
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
/*
//alternative way to fetch it:
    __asm {
        mov eax, fs:[30h]
        mov PEB, eax
    };
    return (PPEB)PEB;
*/
#endif
}

inline PLDR_MODULE get_ldr_module()
{
    PPEB peb = get_peb();
    if (peb == NULL) {
        return NULL;
    }
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY list = ldr->InLoadOrderModuleList;
    
    PLDR_MODULE Flink = *( ( PLDR_MODULE * )( &list ) );
    return Flink;
}

inline WCHAR to_lowercase(WCHAR c1)
{
    if (c1 <= L'Z' && c1 >= L'A') {
        c1 = (c1 - L'A') + L'a';
    }
    return c1;
}

bool is_wanted_module(LPWSTR curr_name, LPWSTR wanted_name)
{
    if (wanted_name == NULL || curr_name == NULL) return false;

    static SIZE_T wanted_name_len = wcslen(wanted_name);
    SIZE_T curr_name_len = wcslen(curr_name);
    if (curr_name_len < wanted_name_len) return false;

    WCHAR *ptr = &(curr_name[curr_name_len - wanted_name_len]);
    SIZE_T i = 0;
    for (; i < wanted_name_len; i++) {
        if (to_lowercase(ptr[i]) != to_lowercase(wanted_name[i])) {
            return false;
        }
    }
    if (i == wanted_name_len) return true;
    return false;
}

LPVOID get_module_base(LPWSTR module_name)
{
    PLDR_MODULE curr_module = get_ldr_module();
    while (curr_module != NULL && curr_module->BaseAddress != NULL) {
        if (is_wanted_module(curr_module->BaseDllName, module_name)) {
            return curr_module->BaseAddress;
        }
        curr_module = (PLDR_MODULE) curr_module->InLoadOrderModuleList.Flink;
    }
    return NULL;
}
