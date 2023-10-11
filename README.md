## Intro
- This is a working but non-optimized project that manually maps a DLL inside a x64 executable.
- This works by writing the DLL along with its sections inside the remote process using WriteProcessMemory,
    fixing up the addresses by using the reloc section if the DLL wasn't loaded at its preferred base,
    resolving the imports by getting each function in the IAT of the DLL and using GetProcAddress to get their correct address,
    Using section headers informations to restore correct page protection for the loaded sections in the Remote Process memory
    and finally creating a remote thread which calls the DLlentry with it's base address for execution
- The benfits of this technique is that the DLL informations will not be present inside the PEB.Ldr linked list of the remote process


## DLL format
Since this program uses CreateRemoteThread to execute the DLL entry point, we can only pass one parameter, so checking `fdwReason` won't work.

Here is what the DLL source code should look like:

```cpp
#include <windows.h>

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved)  // reserved
{
    MessageBoxA(0, "Hello World!", "Warning", MB_OK);
    return TRUE;
}
```

## Building
To build the program run `nmake` in the home directory

## Notes
  - this program does not check if the DLL is already loaded so you can load multiple times the same DLL in a process
  - this program does not treat delay-loaded DLL's in the imports
  - To use this program you should provide the DLL name and the pid of the remote process as arguments
