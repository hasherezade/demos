#include <Windows.h>

#include "reflective/peb_lookup.h"
#include "reflective/exports_lookup.h"
#include "reflective/reflective_imports_load.h"

#include "start_actions.h"

int main(int argc, char **argv)
{
#if defined(_WIN64)
#error 64 bit not supported! Compile this program as 32bit application!
    return -1;
#else
    if (!apply_imports32()) {
        return -2;
    }
    return start_actions(argc, argv);
#endif
}
