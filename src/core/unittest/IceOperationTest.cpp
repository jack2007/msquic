/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit tests for private ICE worker-operation cleanup.

--*/

#include "main.h"

extern "C"
void
QuicWorkerLoopCleanup(
    QUIC_WORKER* Worker);

namespace {

struct IceOperationCleanupContext {
    uint32_t ExecuteCount {0};
    uint32_t CancelCount {0};
};

void
QUIC_API
IceOperationExecute(void* Context)
{
    static_cast<IceOperationCleanupContext*>(Context)->ExecuteCount++;
}

void
QUIC_API
IceOperationCancel(void* Context)
{
    static_cast<IceOperationCleanupContext*>(Context)->CancelCount++;
}

}

TEST(IceOperationTest, WorkerCleanupCancelsAndReleasesInOrder)
{
    QUIC_BINDING Binding {};
    Binding.RefCount = 2;
    Binding.IceExtension.Configured = TRUE;
    CxPlatRundownInitialize(&Binding.IceExtension.UpcallRundown);
    ASSERT_TRUE(CxPlatRundownAcquire(&Binding.IceExtension.UpcallRundown));

    QUIC_PARTITION Partition {};
    CxPlatPoolInitialize(
        FALSE,
        sizeof(QUIC_OPERATION),
        QUIC_POOL_OPER,
        &Partition.OperPool);
    QUIC_OPERATION* Operation =
        static_cast<QUIC_OPERATION*>(
            CxPlatPoolAlloc(&Partition.OperPool));
    ASSERT_NE(nullptr, Operation);

    IceOperationCleanupContext CallbackContext;
    Operation->Type = QUIC_OPER_TYPE_ICE;
    Operation->FreeAfterProcess = TRUE;
    Operation->ICE.Binding = &Binding;
    Operation->ICE.Operation.Size = sizeof(Operation->ICE.Operation);
    Operation->ICE.Operation.Version = QUIC_ICE_DATAPATH_VERSION_1;
    Operation->ICE.Operation.Context = &CallbackContext;
    Operation->ICE.Operation.Execute = IceOperationExecute;
    Operation->ICE.Operation.Cancel = IceOperationCancel;
    Operation->ICE.OwnsContext = TRUE;
    Operation->ICE.HasRundown = TRUE;
    Operation->ICE.HasBindingRef = TRUE;

    QUIC_WORKER Worker {};
    Worker.Partition = &Partition;
    Worker.IceOperationCount = 1;
    CxPlatListInitializeHead(&Worker.Connections);
    Worker.PriorityConnectionsTail = &Worker.Connections.Flink;
    CxPlatListInitializeHead(&Worker.Listeners);
    CxPlatListInitializeHead(&Worker.Operations);
    CxPlatListInsertTail(&Worker.Operations, &Operation->Link);

    QuicWorkerLoopCleanup(&Worker);

    EXPECT_EQ(0u, CallbackContext.ExecuteCount);
    EXPECT_EQ(1u, CallbackContext.CancelCount);
    EXPECT_EQ(0u, Worker.IceOperationCount);
    EXPECT_TRUE(CxPlatListIsEmpty(&Worker.Operations));
    // The cleanup callback returned before rundown release, which in turn
    // preceded the binding reference release. Keeping a second reference
    // avoids invoking full binding uninitialization for this focused unit.
    EXPECT_EQ(1u, Binding.RefCount);

    CxPlatPoolUninitialize(&Partition.OperPool);
    CxPlatRundownUninitialize(&Binding.IceExtension.UpcallRundown);
}
