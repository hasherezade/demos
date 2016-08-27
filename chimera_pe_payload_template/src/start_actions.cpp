#include <Windows.h>
#include "test.h"


//this is the new main function, after initialization
//fill it as you like
int start_actions(int argc, char **argv)
{
    if (deploy_test() == false) {
        return -1;
    }
    return 0;
}
