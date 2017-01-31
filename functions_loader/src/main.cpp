#include <windows.h>
#include <stdio.h>

#include "peb_lookup.h"
#include "exports_lookup.h"

#include "usage_demo.h"
#include "test.h"

int main(int argc, char *argv[])
{
    if (!test_loading()) {
        system("pause");
        return -1;
    }
    load_and_popup();
    system("pause");
    return 0;
}
