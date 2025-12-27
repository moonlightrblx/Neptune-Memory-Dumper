#pragma once
#include <ntddk.h>
#include "../defs.h"
#include "../utils.h"

UINT64 GetProcessCr3(PEPROCESS Process) {
    if (!Process) return 0;
    uintptr_t process_dirbase = *(uintptr_t*)((UINT8*)Process + 0x28);
    if (process_dirbase == 0)
    {
        ULONG user_diroffset = GetWindowsVersion();
        process_dirbase = *(uintptr_t*)((UINT8*)Process + user_diroffset);
    }
    if ((process_dirbase >> 0x38) == 0x40)
    {
        uintptr_t SavedDirBase = 0;
        bool Attached = false;
        if (!Attached)
        {
            KAPC_STATE apc_state{};
            KeStackAttachProcess(Process, &apc_state);
            SavedDirBase = __readcr3();
            KeUnstackDetachProcess(&apc_state);
            Attached = true;
        }
        if (SavedDirBase) return SavedDirBase;

    }
    return process_dirbase;
}