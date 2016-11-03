#include <windows.h>
#include <stdio.h>

#include "peb_lookup.h"
#include "exports_lookup.h"

#include "usage_demo.h"
#include "test.h"

int main(int argc, char *argv[])
{
#if defined(_WIN64)
    // 64 bit not supported! Compile this program as a 32bit application!
    printf("64 bit not supported! Compile this program as a 32bit application!\n");
    system("pause");
    return -1;
#else
    if (!test_loading()) {
        system("pause");
        return -1;
    }
    load_and_popup();
#endif
    system("pause");
    return 0;
}
