#include "injection.h"
#include <stdio.h>
#include <Psapi.h>

#pragma comment(lib, "psapi.lib")

ULONG_PTR FindImageBase(HANDLE hProc, LPSTR lpCommandline);

int main(int argc, char *argv[])
{
    // usage: ./DllInjector.exe targetFile dllName
    int mode = 2;
    //printf("进程注入模式[1-3]:");
    //scanf("%d", &mode);
    //mode--;
    if (argc < 2) {
        printf("usage: ./DllInjector.exe targetFile dllName");
        return 0;
    }

    BOOL injResult;
    switch (mode)
    {
        case INJ_ORIGIN:
            //injResult = InjAtOriginalSection(argv[1], argv[2]);
            break;
        case INJ_EXTEND:
            //injResult = InjByExtendingLastSection(argv[1], argv[2]);
            break;
        case INJ_ADD:
            injResult = InjByAddingNewSection(argv[1], argv[2], ".inj");
            break;
    default:
        printf("不支持的注入模式\n");
        return FALSE;
    }

    return 0;
}