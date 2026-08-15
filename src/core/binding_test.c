/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Test-local probes for ICE binding state. This file is compiled only into
    msquictest and is never linked into the MsQuic library.

--*/

#include "precomp.h"

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicBindingIceGetTestState(
    _In_ void* BindingContext,
    _Out_ uint16_t* LocalMtu,
    _Out_ uint64_t* SendExtensionDrops,
    _Out_ uint64_t* RecvExtensionDrops
    )
{
    if (BindingContext == NULL ||
        LocalMtu == NULL ||
        SendExtensionDrops == NULL ||
        RecvExtensionDrops == NULL) {
        return FALSE;
    }

    QUIC_BINDING* Binding = (QUIC_BINDING*)BindingContext;
    QUIC_ADDR RemoteAddress = {0};
    QuicAddrSetFamily(&RemoteAddress, QUIC_ADDRESS_FAMILY_INET);
    RemoteAddress.Ipv4.sin_addr.s_addr = htonl(0x7F000001);
    QuicAddrSetPort(&RemoteAddress, 9);

    CXPLAT_ROUTE Route = {0};
    BOOLEAN RouteFound = FALSE;
    for (uint16_t Partition = 0;
         Partition < (uint16_t)CxPlatProcCount();
         ++Partition) {
        if (QUIC_SUCCEEDED(
                CxPlatSocketGetRouteForPartition(
                    Binding->Socket,
                    Partition,
                    &RemoteAddress,
                    &Route))) {
            RouteFound = TRUE;
            break;
        }
    }
    if (!RouteFound) {
        return FALSE;
    }

    *LocalMtu = CxPlatSocketGetLocalMtu(Binding->Socket, &Route);
    *SendExtensionDrops =
        (uint64_t)InterlockedCompareExchange64(
            (int64_t*)&Binding->Stats.Send.ExtensionDrop, 0, 0);
    *RecvExtensionDrops =
        (uint64_t)InterlockedCompareExchange64(
            (int64_t*)&Binding->Stats.Recv.ExtensionDrop, 0, 0);
    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicBindingIceGetWorkerTestState(
    _In_ void* BindingContext,
    _In_ uint16_t PartitionIndex,
    _Out_ uint32_t* IceOperationCount,
    _Out_ uint32_t* StatelessOperationCount,
    _Out_ uint64_t* IceOperationsQueued,
    _Out_ uint64_t* IceOperationsCompleted,
    _Out_ uint64_t* IceOperationsDropped
    )
{
    if (BindingContext == NULL || IceOperationCount == NULL ||
        StatelessOperationCount == NULL || IceOperationsQueued == NULL ||
        IceOperationsCompleted == NULL || IceOperationsDropped == NULL) {
        return FALSE;
    }

    QUIC_BINDING* Binding = (QUIC_BINDING*)BindingContext;
    QUIC_WORKER_POOL* WorkerPool = Binding->IceExtension.WorkerPool;
    if (WorkerPool == NULL || PartitionIndex >= WorkerPool->WorkerCount) {
        return FALSE;
    }
    QUIC_WORKER* Worker =
        &WorkerPool->Workers[PartitionIndex];
    CxPlatDispatchLockAcquire(&Worker->Lock);
    *IceOperationCount = Worker->IceOperationCount;
    *StatelessOperationCount = Worker->OperationCount;
    CxPlatDispatchLockRelease(&Worker->Lock);
    *IceOperationsQueued =
        (uint64_t)InterlockedCompareExchange64(
            (int64_t*)&Worker->IceOperationsQueued, 0, 0);
    *IceOperationsCompleted =
        (uint64_t)InterlockedCompareExchange64(
            (int64_t*)&Worker->IceOperationsCompleted, 0, 0);
    *IceOperationsDropped =
        (uint64_t)InterlockedCompareExchange64(
            (int64_t*)&Worker->IceOperationsDropped, 0, 0);
    return TRUE;
}
