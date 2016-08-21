#pragma once
#include <Windows.h>

typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type: 4;
} BASE_RELOCATION_ENTRY;

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

bool has_relocations(BYTE *pe_buffer)
{
    //fetch relocation table from current image:
    PIMAGE_NT_HEADERS nt_headers = get_nt_hrds((BYTE*) pe_buffer);
    if (nt_headers == NULL) return false;

    IMAGE_DATA_DIRECTORY relocDir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.VirtualAddress == NULL) {
        return false;
    }
    return true;
}

BOOL apply_reloc_block(BASE_RELOCATION_ENTRY *block, SIZE_T entriesNum, DWORD page, LONG oldBase, LONG newBase, PVOID modulePtr)
{
    BASE_RELOCATION_ENTRY* entry = block;
    SIZE_T i = 0;
    for (i = 0; i < entriesNum; i++) {
        DWORD offset = entry->Offset;
        DWORD type = entry->Type;
        if (entry == NULL || type == 0 || offset == 0) {
            break;
        }
        if (type != 3) {
            printf("Not supported relocations format at %d: %d\n", i, type);
            return FALSE;
        }
        DWORD* relocateAddr = (DWORD*) ((ULONG_PTR) modulePtr + page + offset);
        (*relocateAddr) = ((*relocateAddr) - (ULONG_PTR) oldBase) + newBase;
        entry = (BASE_RELOCATION_ENTRY*)((ULONG_PTR) entry + sizeof(WORD));
    }
    printf("[+] Applied %d relocations\n", i);
    return TRUE;
}

bool apply_relocations(LONG newBase, LONG oldBase, PVOID modulePtr)
{
    //fetch relocation table from current image:
    PIMAGE_NT_HEADERS nt_headers = get_nt_hrds((BYTE*) modulePtr);
    if (nt_headers == NULL) {
        return false;
    }

    IMAGE_DATA_DIRECTORY relocDir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.VirtualAddress == NULL) {
        printf ("Cannot relocate - application have no relocation table!\n");
        return false;
    }
    DWORD maxSize = relocDir.Size;
    DWORD parsedSize = 0;

    DWORD relocAddr = relocDir.VirtualAddress;
    IMAGE_BASE_RELOCATION* reloc = NULL;

    while (parsedSize < maxSize) {
        reloc = (IMAGE_BASE_RELOCATION*)(relocAddr + parsedSize + (ULONG_PTR) modulePtr);
        parsedSize += reloc->SizeOfBlock;

        if (reloc->VirtualAddress == NULL || reloc->SizeOfBlock == 0) {
            continue;
        }

        printf("RelocBlock: %p %p\n", reloc->VirtualAddress, reloc->SizeOfBlock);
        
        size_t entriesNum = (reloc->SizeOfBlock - 2 * sizeof(DWORD))  / sizeof(WORD);
        DWORD page = reloc->VirtualAddress;

        BASE_RELOCATION_ENTRY* block = (BASE_RELOCATION_ENTRY*)((ULONG_PTR) reloc + sizeof(DWORD) + sizeof(DWORD));
        if (apply_reloc_block(block, entriesNum, page, oldBase, newBase, modulePtr) == FALSE) {
            return false;
        }
    }
    return true;
}