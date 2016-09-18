#pragma once
#include <Windows.h>

// version for 32bit PE
// WARNIG: we don't want to use any imported functions in here!

#include "pe_hdrs_helper.h"

/*
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
*/

#ifndef TO_LOWERCASE
#define TO_LOWERCASE(c1) c1 = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a': c1;
#endif

bool is_wanted_func(LPSTR curr_name, LPSTR wanted_name)
{
    if (curr_name == NULL || wanted_name == NULL) return false;

    SIZE_T wanted_name_len = strlen(wanted_name);
    SIZE_T curr_name_len = strlen(curr_name);

    if (curr_name_len < wanted_name_len) return false;

    for (size_t i = 0; i < wanted_name_len && i < curr_name_len; i++) {
        char c1 = curr_name[i];
        char c2 = wanted_name[i];
        TO_LOWERCASE(c1);
        TO_LOWERCASE(c2);
        if (c1 != c2) return false;
    }
    return true;
}

LPSTR get_func_name(PVOID modulePtr, DWORD funcNamesAddr, DWORD nameOrdinal )
{
    DWORD offset = sizeof(DWORD) * (nameOrdinal);
    DWORD* funcNameRVA = (DWORD*)(funcNamesAddr + (BYTE*) modulePtr + offset);
    DWORD nameRVA = *funcNameRVA;

    if (nameRVA == NULL) return NULL;

    LPSTR name = (LPSTR)(nameRVA + (BYTE*) modulePtr);
    //printf("Got name: %s | %d\n", name, nameOrdinal);
    return name;
}

SIZE_T ord_lookup(PVOID modulePtr, SIZE_T funcCount, DWORD namesOrdsAddr, DWORD myOrd)
{
    for (SIZE_T i = 0; i < funcCount; i++) {
        WORD* funcOrdRVA = (WORD*)(namesOrdsAddr + (BYTE*) modulePtr + i * sizeof(WORD));
        if (*funcOrdRVA == myOrd) return i;
    }
    return -1;
}

//WARNING: this is a minimalistic version - it doesn't work for the forwarded functions:
PVOID get_exported_func(PVOID modulePtr, LPSTR wanted_name)
{
    IMAGE_DATA_DIRECTORY *exportsDir = get_pe_directory(modulePtr, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (exportsDir == NULL) return NULL;

    DWORD maxSize = exportsDir->Size;
    DWORD parsedSize = 0;

    DWORD expAddr = exportsDir->VirtualAddress;
    if (expAddr == 0) return NULL;

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR) modulePtr);
    SIZE_T funcCount = exp->NumberOfFunctions;
    
    DWORD funcsAddr = exp->AddressOfFunctions;
    DWORD funcNamesAddr = exp->AddressOfNames;
    DWORD namesOrdsAddr = exp->AddressOfNameOrdinals;

    DWORD offset = 0;
    for (SIZE_T i = 0; i < funcCount; i++, offset+=sizeof(DWORD)) {
        DWORD* funcRVA = (DWORD*)(funcsAddr + (BYTE*) modulePtr + offset);
        WORD* funcOrdRVA = (WORD*)(namesOrdsAddr + (BYTE*) modulePtr + i*sizeof(WORD));

        DWORD func = (*funcRVA);
        if (func == NULL) return NULL;
        SIZE_T namePos = ord_lookup( modulePtr,  funcCount,  namesOrdsAddr,  i);
        if (namePos == -1 || namePos == 0) continue;

        LPSTR name = get_func_name(modulePtr, funcNamesAddr, namePos);
        if (is_wanted_func(name, wanted_name)) {
            return (BYTE*) modulePtr + func;
        }
    }
    //function not found
    return NULL;
}