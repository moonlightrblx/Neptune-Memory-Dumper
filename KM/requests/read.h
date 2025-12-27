#include <ntddk.h>
#include "../defs.h"
#pragma once

NTSTATUS HandleReadRequest(PReadWriteRequest Request) {
    if (Request->Security != PaysonSecurity)
        return STATUS_UNSUCCESSFUL;

    if (!Request->ProcessId)
        return STATUS_UNSUCCESSFUL;

    PEPROCESS Process = NULL;
    PsLookupProcessByProcessId((HANDLE)Request->ProcessId, &Process);
    if (!Process)
        return STATUS_UNSUCCESSFUL;

    ULONGLONG ProcessBase = GetProcessCr3(Process);
    ObDereferenceObject(Process);

    SIZE_T TotalSize = Request->Size;
    SIZE_T BytesCopied = 0;

    while (BytesCopied < TotalSize) {
        SIZE_T CurrentOffset = BytesCopied;
        INT64 PhysicalAddress = TranslateLinearAddress(ProcessBase, (ULONG64)Request->Address + CurrentOffset);
        if (!PhysicalAddress)
            break;

        ULONG64 Remaining = TotalSize - BytesCopied;
        ULONG64 ChunkSize = FindMin(PAGE_SIZE - (PhysicalAddress & 0xFFF), Remaining);
        SIZE_T BytesRead = 0;

        NTSTATUS Status = ReadPhysicalMemory(PVOID(PhysicalAddress), (PVOID)((ULONG64)Request->Buffer + CurrentOffset), ChunkSize, &BytesRead);
        if (!NT_SUCCESS(Status) || BytesRead == 0)
            break;

        BytesCopied += BytesRead;
    }

    Request->Size = BytesCopied;
    return (BytesCopied == TotalSize) ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}
