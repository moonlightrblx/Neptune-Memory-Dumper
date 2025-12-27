#pragma once
#include <ntddk.h>
#include "../defs.h"

NTSTATUS HandleBaseAddressRequest(PBaseAddressRequest Request) {
    if (Request->Security != PaysonSecurity)
        return STATUS_UNSUCCESSFUL;

    if (!Request->ProcessId)
        return STATUS_UNSUCCESSFUL;

    PEPROCESS Process = NULL;
    PsLookupProcessByProcessId((HANDLE)Request->ProcessId, &Process);
    if (!Process)
        return STATUS_UNSUCCESSFUL;

    ULONGLONG ImageBase = (ULONGLONG)PsGetProcessSectionBaseAddress(Process);
    if (!ImageBase)
        return STATUS_UNSUCCESSFUL;

    RtlCopyMemory(Request->Address, &ImageBase, sizeof(ImageBase));
    ObDereferenceObject(Process);

    return STATUS_SUCCESS;
}