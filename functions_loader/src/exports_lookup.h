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

    size_t wanted_name_len = strlen(wanted_name);
    size_t curr_name_len = strlen(curr_name);

    if (curr_name_len != wanted_name_len) return false;

    for (size_t i = 0; i < wanted_name_len; i++) {
        char c1 = curr_name[i];
        char c2 = wanted_name[i];
        TO_LOWERCASE(c1);
        TO_LOWERCASE(c2);
        if (c1 != c2) return false;
    }
    return true;
}

//WARNING: this is a minimalistic version - it doesn't work for the forwarded functions:
PVOID get_exported_func(PVOID modulePtr, LPSTR wanted_name)
{
    IMAGE_DATA_DIRECTORY *exportsDir = get_pe_directory(modulePtr, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (exportsDir == NULL) return NULL;

    DWORD expAddr = exportsDir->VirtualAddress;
    if (expAddr == 0) return NULL;

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR) modulePtr);
    SIZE_T namesCount = exp->NumberOfNames;

    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD funcNamesListRVA = exp->AddressOfNames;
    DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

    //go through names:
    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*) modulePtr + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*) modulePtr + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*) modulePtr + (*nameIndex) * sizeof(DWORD));

        LPSTR name = (LPSTR)(*nameRVA + (BYTE*) modulePtr);       
        if (is_wanted_func(name, wanted_name)) {
            return (BYTE*) modulePtr + (*funcRVA);
        }
    }
    //function not found
    return NULL;
}