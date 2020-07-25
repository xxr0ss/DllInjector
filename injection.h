#include "Image.h"
#include <Windows.h>

// BOOL CreateProcessA(
//   LPCSTR                lpApplicationName,
//   LPSTR                 lpCommandLine,
//   LPSECURITY_ATTRIBUTES lpProcessAttributes,
//   LPSECURITY_ATTRIBUTES lpThreadAttributes,
//   BOOL                  bInheritHandles,
//   DWORD                 dwCreationFlags,
//   LPVOID                lpEnvironment,
//   LPCSTR                lpCurrentDirectory,
//   LPSTARTUPINFOA        lpStartupInfo,
//   LPPROCESS_INFORMATION lpProcessInformation
// );

#define INJ_ORIGIN 0
#define INJ_EXTEND 1
#define INJ_ADD 2

//BOOL InjAtOriginalSection(LPSTR targetFile, LPSTR dllname);
//BOOL InjByExtendingLastSection(LPSTR targetFile, LPSTR dllname);
BOOL InjByAddingNewSection(LPSTR targetFile, LPSTR dllname, LPSTR newSecName);

ULONG_PTR FindImageBase(HANDLE hProc,LPSTR lpCommandLine);