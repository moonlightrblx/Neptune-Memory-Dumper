#include <ntifs.h>
#include <windef.h>
#include <intrin.h>
#include "defs.h"
#include "requests/read.h"
#include "requests/base.h"
#include "requests/cr3.h"

UNICODE_STRING DriverName, SymbolicLinkName;

ULONG64 FindMin(INT32 A, SIZE_T B) {
    INT32 BInt = (INT32)B;
    return (((A) < (BInt)) ? (A) : (BInt));
}

NTSTATUS IoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS Status = {};
    ULONG BytesReturned = {};
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    ULONG IoControlCode = Stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG InputBufferLength = Stack->Parameters.DeviceIoControl.InputBufferLength;

    if (IoControlCode == PaysonRead) {
        if (InputBufferLength == sizeof(ReadWriteRequest)) {
            PReadWriteRequest Request = (PReadWriteRequest)(Irp->AssociatedIrp.SystemBuffer);
            Status = HandleReadRequest(Request);
            BytesReturned = sizeof(ReadWriteRequest);
        }
        else {
            Status = STATUS_INFO_LENGTH_MISMATCH;
            BytesReturned = 0;
        }
    }
    else if (IoControlCode == PaysonBase) {
        if (InputBufferLength == sizeof(BaseAddressRequest)) {
            PBaseAddressRequest Request = (PBaseAddressRequest)(Irp->AssociatedIrp.SystemBuffer);
            Status = HandleBaseAddressRequest(Request);
            BytesReturned = sizeof(BaseAddressRequest);
        }
        else {
            Status = STATUS_INFO_LENGTH_MISMATCH;
            BytesReturned = 0;
        }
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = BytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

NTSTATUS UnsupportedDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Irp->IoStatus.Status;
}

NTSTATUS DispatchHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    switch (Stack->MajorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_CLOSE:
        break;
    default:
        break;
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}

void UnloadDriver(PDRIVER_OBJECT DriverObject) {
    NTSTATUS Status = {};

    Status = IoDeleteSymbolicLink(&SymbolicLinkName);

    if (!NT_SUCCESS(Status))
        return;

    IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS InitializeDriver(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status = STATUS_SUCCESS;
    PDEVICE_OBJECT DeviceObject = NULL;

    RtlInitUnicodeString(&DriverName, L"\\Device\\{PaysonMemoryDumper}");
    RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\{PaysonMemoryDumper}");

    Status = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = IoCreateSymbolicLink(&SymbolicLinkName, &DriverName);
    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = &UnsupportedDispatch;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = &DispatchHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = &DispatchHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &IoControlHandler;
    DriverObject->DriverUnload = &UnloadDriver;

    DeviceObject->Flags |= DO_BUFFERED_IO;
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return Status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("\nMade By github.com/paysonism small changes + fixes github.com/moonlightrblx");

    return IoCreateDriver(NULL, &InitializeDriver);
}
