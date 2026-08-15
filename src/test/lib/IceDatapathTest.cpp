/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "../../core/precomp.h"
#undef QUIC_API_ENABLE_PREVIEW_FEATURES
#include "precomp.h"
#undef min
#undef max
#include "gtest/gtest.h"
#include "msquic_ice.h"

#include <atomic>
#include <array>
#include <cstdint>
#include <thread>
#ifdef __linux__
#include <netinet/udp.h>
#endif

namespace {

struct IceCallbackContext {
    std::atomic<uint32_t> BoundCount {0};
    std::atomic<uint32_t> UnboundCount {0};
    CxPlatEvent BoundEvent;
    CxPlatEvent UnboundEvent;
    CxPlatEvent BoundEntered;
    CxPlatEvent AllowBoundReturn;
    QUIC_ICE_BINDING_API_V1 Binding {};
    QUIC_ADDR LocalAddress {};
    std::atomic<uint32_t> RelayCount {0};
    std::atomic<uint32_t> RelayBytes {0};
    std::atomic<uint32_t> RelayMaxLength {0};
    std::atomic<QUIC_STATUS> RelaySendStatus {QUIC_STATUS_SUCCESS};
    CxPlatEvent RelayEvent;
    CxPlatEvent RelayEntered;
    CxPlatEvent AllowRelayReturn;
    std::atomic<bool> BlockRelay {false};
    std::atomic<bool> ReenterControlFromRelay {false};
    QUIC_ADDR ControlRemoteAddress {};
    std::atomic<uint16_t> ControlPartitionIndex {UINT16_MAX};
    std::array<uint8_t, 8> ControlBytes {{
        0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42}};
    std::atomic<QUIC_STATUS> RelayControlStatus {QUIC_STATUS_ABORTED};
    bool SelectPathOnBound {false};
    QUIC_ICE_PATH_TYPE BoundPath {QUIC_ICE_PATH_DIRECT};
    std::atomic<QUIC_STATUS> BoundPathStatus {QUIC_STATUS_ABORTED};
    bool SendControlOnBound {false};
    std::atomic<QUIC_STATUS> BoundControlStatus {QUIC_STATUS_ABORTED};
    bool SendControlOnUnbound {false};
    std::atomic<QUIC_STATUS> UnboundControlStatus {QUIC_STATUS_ABORTED};
    bool SelectPathOnUnbound {false};
    std::atomic<QUIC_STATUS> UnboundPathStatus {QUIC_STATUS_ABORTED};
    HQUIC StopListenerOnBound {nullptr};
    bool BlockBound {false};
    enum class RxAction {
        Pass,
        Consumed,
        Reinject,
        MismatchedDisposition,
        BeforeBuffer,
        OutOfBounds,
        OverflowLength,
        NullInnerBuffer,
        EmptyInnerBuffer,
        WildcardRemote,
        ZeroPortRemote,
        UnknownDisposition,
        ReinjectFullAlternateRemote,
        ReinjectFirstThenPass,
        ConsumedFirstThenPass
    };
    std::atomic<RxAction> Action {RxAction::Pass};
    std::atomic<uint32_t> ReceiveCount {0};
    CxPlatEvent ReceiveEvent;
    CxPlatEvent ReceiveEntered;
    CxPlatEvent AllowReceiveReturn;
    std::atomic<bool> BlockReceive {false};
    CxPlatEvent SecondReceiveEntered;
    CxPlatEvent AllowSecondReceiveReturn;
    std::atomic<bool> BlockSecondReceive {false};
    CxPlatLock ReceiveLock;
    uint32_t LastReceiveLength {0};
    std::array<uint8_t, 24> LastReceiveBytes {};
    QUIC_ADDR LastReceiveLocalAddress {};
    QUIC_ADDR LastReceiveRemoteAddress {};
    QUIC_ADDR LastInnerRemoteAddress {};
    std::array<QUIC_ADDR, 2> ReceiveRemoteAddresses {};
    uint16_t LastReceivePartitionIndex {0};
    uint8_t LastReceiveTypeOfService {0};
};

QUIC_ADDR
MakeAlternateRemoteAddress(
    const QUIC_ADDR& OuterAddress)
{
    QUIC_ADDR AlternateAddress = OuterAddress;
    const uint16_t OuterPort = QuicAddrGetPort(&OuterAddress);
    QuicAddrSetPort(
        &AlternateAddress,
        OuterPort == UINT16_MAX ? OuterPort - 1 : OuterPort + 1);
    return AlternateAddress;
}

QUIC_ICE_RX_DISPOSITION
QUIC_API
IceReceive(
    void* Context,
    const QUIC_ICE_DATAGRAM_VIEW_V1* Input,
    QUIC_ICE_RX_OUTPUT_V1* Output)
{
    auto* CallbackContext = static_cast<IceCallbackContext*>(Context);
    const uint32_t ReceiveIndex =
        CallbackContext->ReceiveCount.fetch_add(1, std::memory_order_relaxed);
    struct ReceiveEventGuard {
        CxPlatEvent& Event;
        ~ReceiveEventGuard() { Event.Set(); }
    } EventGuard {CallbackContext->ReceiveEvent};
    {
        LockGuard LockScope{CallbackContext->ReceiveLock};
        CallbackContext->LastReceiveLength = Input->BufferLength;
        CxPlatCopyMemory(
            CallbackContext->LastReceiveBytes.data(),
            Input->Buffer,
            Input->BufferLength < CallbackContext->LastReceiveBytes.size() ?
                Input->BufferLength : (uint32_t)CallbackContext->LastReceiveBytes.size());
        CallbackContext->LastReceiveLocalAddress = Input->LocalAddress;
        CallbackContext->LastReceiveRemoteAddress = Input->RemoteAddress;
        if (ReceiveIndex < CallbackContext->ReceiveRemoteAddresses.size()) {
            CallbackContext->ReceiveRemoteAddresses[ReceiveIndex] = Input->RemoteAddress;
        }
        CallbackContext->LastReceivePartitionIndex = Input->PartitionIndex;
        CallbackContext->LastReceiveTypeOfService = Input->TypeOfService;
    }
    *Output = {};

    const auto Action = CallbackContext->Action.load(std::memory_order_acquire);
    CallbackContext->ReceiveEntered.Set();
    if (CallbackContext->BlockReceive.load(std::memory_order_acquire)) {
        CallbackContext->AllowReceiveReturn.WaitForever();
    }
    switch (Action) {
    case IceCallbackContext::RxAction::Pass:
        Output->Disposition = QUIC_ICE_RX_PASS;
        return QUIC_ICE_RX_PASS;
    case IceCallbackContext::RxAction::Consumed:
        Output->Disposition = QUIC_ICE_RX_CONSUMED;
        return QUIC_ICE_RX_CONSUMED;
    case IceCallbackContext::RxAction::Reinject:
        Output->Disposition = QUIC_ICE_RX_REINJECT_QUIC;
        Output->InnerBuffer = Input->Buffer + 4;
        Output->InnerBufferLength = Input->BufferLength - 4;
        Output->InnerRemoteAddress =
            MakeAlternateRemoteAddress(Input->RemoteAddress);
        {
            LockGuard LockScope{CallbackContext->ReceiveLock};
            CallbackContext->LastInnerRemoteAddress = Output->InnerRemoteAddress;
        }
        return QUIC_ICE_RX_REINJECT_QUIC;
    case IceCallbackContext::RxAction::MismatchedDisposition:
        Output->Disposition = QUIC_ICE_RX_CONSUMED;
        return QUIC_ICE_RX_PASS;
    case IceCallbackContext::RxAction::BeforeBuffer:
        Output->Disposition = QUIC_ICE_RX_REINJECT_QUIC;
        Output->InnerBuffer = reinterpret_cast<const uint8_t*>(
            reinterpret_cast<uintptr_t>(Input->Buffer) - 1);
        Output->InnerBufferLength = 1;
        Output->InnerRemoteAddress = Input->RemoteAddress;
        return QUIC_ICE_RX_REINJECT_QUIC;
    case IceCallbackContext::RxAction::OutOfBounds:
        Output->Disposition = QUIC_ICE_RX_REINJECT_QUIC;
        Output->InnerBuffer = Input->Buffer + Input->BufferLength;
        Output->InnerBufferLength = 1;
        Output->InnerRemoteAddress = Input->RemoteAddress;
        return QUIC_ICE_RX_REINJECT_QUIC;
    case IceCallbackContext::RxAction::OverflowLength:
        Output->Disposition = QUIC_ICE_RX_REINJECT_QUIC;
        Output->InnerBuffer = Input->Buffer + 1;
        Output->InnerBufferLength = UINT32_MAX;
        Output->InnerRemoteAddress = Input->RemoteAddress;
        return QUIC_ICE_RX_REINJECT_QUIC;
    case IceCallbackContext::RxAction::NullInnerBuffer:
        Output->Disposition = QUIC_ICE_RX_REINJECT_QUIC;
        Output->InnerBufferLength = 1;
        Output->InnerRemoteAddress = Input->RemoteAddress;
        return QUIC_ICE_RX_REINJECT_QUIC;
    case IceCallbackContext::RxAction::EmptyInnerBuffer:
        Output->Disposition = QUIC_ICE_RX_REINJECT_QUIC;
        Output->InnerBuffer = Input->Buffer;
        Output->InnerRemoteAddress = Input->RemoteAddress;
        return QUIC_ICE_RX_REINJECT_QUIC;
    case IceCallbackContext::RxAction::WildcardRemote:
        Output->Disposition = QUIC_ICE_RX_REINJECT_QUIC;
        Output->InnerBuffer = Input->Buffer + 4;
        Output->InnerBufferLength = Input->BufferLength - 4;
        QuicAddrSetFamily(&Output->InnerRemoteAddress, QUIC_ADDRESS_FAMILY_INET);
        QuicAddrSetPort(&Output->InnerRemoteAddress, 443);
        return QUIC_ICE_RX_REINJECT_QUIC;
    case IceCallbackContext::RxAction::ZeroPortRemote:
        Output->Disposition = QUIC_ICE_RX_REINJECT_QUIC;
        Output->InnerBuffer = Input->Buffer + 4;
        Output->InnerBufferLength = Input->BufferLength - 4;
        Output->InnerRemoteAddress = Input->RemoteAddress;
        QuicAddrSetPort(&Output->InnerRemoteAddress, 0);
        return QUIC_ICE_RX_REINJECT_QUIC;
    case IceCallbackContext::RxAction::UnknownDisposition:
        Output->Disposition = (QUIC_ICE_RX_DISPOSITION)99;
        return (QUIC_ICE_RX_DISPOSITION)99;
    case IceCallbackContext::RxAction::ReinjectFullAlternateRemote:
        Output->Disposition = QUIC_ICE_RX_REINJECT_QUIC;
        Output->InnerBuffer = Input->Buffer;
        Output->InnerBufferLength = Input->BufferLength;
        Output->InnerRemoteAddress =
            MakeAlternateRemoteAddress(Input->RemoteAddress);
        {
            LockGuard LockScope{CallbackContext->ReceiveLock};
            CallbackContext->LastInnerRemoteAddress = Output->InnerRemoteAddress;
        }
        return QUIC_ICE_RX_REINJECT_QUIC;
    case IceCallbackContext::RxAction::ReinjectFirstThenPass:
        if (ReceiveIndex != 0) {
            Output->Disposition = QUIC_ICE_RX_PASS;
            return QUIC_ICE_RX_PASS;
        }
        Output->Disposition = QUIC_ICE_RX_REINJECT_QUIC;
        Output->InnerBuffer = Input->Buffer + 4;
        Output->InnerBufferLength = Input->BufferLength - 4;
        Output->InnerRemoteAddress =
            MakeAlternateRemoteAddress(Input->RemoteAddress);
        {
            LockGuard LockScope{CallbackContext->ReceiveLock};
            CallbackContext->LastInnerRemoteAddress = Output->InnerRemoteAddress;
        }
        return QUIC_ICE_RX_REINJECT_QUIC;
    case IceCallbackContext::RxAction::ConsumedFirstThenPass:
        if (ReceiveIndex == 0) {
            Output->Disposition = QUIC_ICE_RX_CONSUMED;
            return QUIC_ICE_RX_CONSUMED;
        }
        Output->Disposition = QUIC_ICE_RX_PASS;
        CallbackContext->SecondReceiveEntered.Set();
        if (CallbackContext->BlockSecondReceive.load(
                std::memory_order_acquire)) {
            CallbackContext->AllowSecondReceiveReturn.WaitForever();
        }
        return QUIC_ICE_RX_PASS;
    }

    return QUIC_ICE_RX_PASS;
}

QUIC_STATUS
QUIC_API
IceSendRelayDatagram(
    void* Context,
    const uint8_t*,
    uint32_t BufferLength)
{
    auto* CallbackContext = static_cast<IceCallbackContext*>(Context);
    CallbackContext->RelayCount.fetch_add(1, std::memory_order_relaxed);
    CallbackContext->RelayBytes.fetch_add(BufferLength, std::memory_order_relaxed);
    uint32_t PreviousMax =
        CallbackContext->RelayMaxLength.load(std::memory_order_relaxed);
    while (PreviousMax < BufferLength &&
           !CallbackContext->RelayMaxLength.compare_exchange_weak(
               PreviousMax,
               BufferLength,
               std::memory_order_relaxed,
               std::memory_order_relaxed)) {
    }
    CallbackContext->RelayEntered.Set();
    if (CallbackContext->ReenterControlFromRelay.exchange(
            false, std::memory_order_acq_rel)) {
        CallbackContext->RelayControlStatus.store(
            CallbackContext->Binding.SendControl(
                CallbackContext->Binding.BindingContext,
                CallbackContext->ControlPartitionIndex.load(
                    std::memory_order_acquire),
                &CallbackContext->ControlRemoteAddress,
                CallbackContext->ControlBytes.data(),
                (uint32_t)CallbackContext->ControlBytes.size()),
            std::memory_order_release);
    }
    if (CallbackContext->BlockRelay.load(std::memory_order_acquire)) {
        CallbackContext->AllowRelayReturn.WaitForever();
    }
    CallbackContext->RelayEvent.Set();
    return CallbackContext->RelaySendStatus.load(std::memory_order_acquire);
}

void
QUIC_API
IceBound(
    void* Context,
    const QUIC_ICE_BINDING_API_V1* Binding,
    const QUIC_ADDR* LocalAddress)
{
    auto* CallbackContext = static_cast<IceCallbackContext*>(Context);
    CallbackContext->Binding = *Binding;
    CallbackContext->LocalAddress = *LocalAddress;
    CallbackContext->BoundCount.fetch_add(1, std::memory_order_relaxed);
    if (CallbackContext->SelectPathOnBound) {
        CallbackContext->BoundPathStatus.store(
            Binding->SetSelectedPath(
                Binding->BindingContext, CallbackContext->BoundPath),
            std::memory_order_release);
    }
    if (CallbackContext->SendControlOnBound) {
        QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
        for (uint16_t Partition = 0;
             Partition < (uint16_t)CxPlatProcCount();
             ++Partition) {
            Status =
                Binding->SendControl(
                    Binding->BindingContext,
                    Partition,
                    &CallbackContext->ControlRemoteAddress,
                    CallbackContext->ControlBytes.data(),
                    (uint32_t)CallbackContext->ControlBytes.size());
            if (QUIC_SUCCEEDED(Status)) {
                CallbackContext->ControlPartitionIndex.store(
                    Partition, std::memory_order_release);
                break;
            }
        }
        CallbackContext->BoundControlStatus.store(
            Status, std::memory_order_release);
    }
    CallbackContext->BoundEvent.Set();
    CallbackContext->BoundEntered.Set();
    if (CallbackContext->StopListenerOnBound != nullptr) {
        MsQuic->ListenerStop(CallbackContext->StopListenerOnBound);
    }
    if (CallbackContext->BlockBound) {
        CallbackContext->AllowBoundReturn.WaitForever();
    }
}

void
QUIC_API
IceUnbound(void* Context)
{
    auto* CallbackContext = static_cast<IceCallbackContext*>(Context);
    if (CallbackContext->SelectPathOnUnbound) {
        CallbackContext->UnboundPathStatus.store(
            CallbackContext->Binding.SetSelectedPath(
                CallbackContext->Binding.BindingContext,
                QUIC_ICE_PATH_DIRECT),
            std::memory_order_release);
    }
    if (CallbackContext->SendControlOnUnbound) {
        CallbackContext->UnboundControlStatus.store(
            CallbackContext->Binding.SendControl(
                CallbackContext->Binding.BindingContext,
                CallbackContext->ControlPartitionIndex.load(
                    std::memory_order_acquire),
                &CallbackContext->ControlRemoteAddress,
                CallbackContext->ControlBytes.data(),
                (uint32_t)CallbackContext->ControlBytes.size()),
            std::memory_order_release);
    }
    CallbackContext->UnboundCount.fetch_add(1, std::memory_order_relaxed);
    CallbackContext->UnboundEvent.Set();
}

QUIC_ICE_DATAPATH_CONFIG_V1
MakeIceConfig(IceCallbackContext* Context)
{
    QUIC_ICE_DATAPATH_CONFIG_V1 Config {};
    Config.Size = sizeof(Config);
    Config.Version = QUIC_ICE_DATAPATH_VERSION_1;
    Config.Context = Context;
    Config.Receive = IceReceive;
    Config.SendRelayDatagram = IceSendRelayDatagram;
    Config.Bound = IceBound;
    Config.Unbound = IceUnbound;
    return Config;
}

uint16_t
GetIceBindingLocalMtu(
    const IceCallbackContext& Context)
{
    auto* Binding =
        static_cast<QUIC_BINDING*>(Context.Binding.BindingContext);
    CXPLAT_SOCKET* Socket = Binding->Socket;
    QUIC_ADDR RemoteAddress {};
    QuicAddrSetFamily(&RemoteAddress, QUIC_ADDRESS_FAMILY_INET);
    RemoteAddress.Ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    QuicAddrSetPort(&RemoteAddress, 9);
    for (uint16_t Partition = 0;
         Partition < (uint16_t)CxPlatProcCount();
         ++Partition) {
        CXPLAT_ROUTE Route {};
        if (QUIC_SUCCEEDED(
                CxPlatSocketGetRouteForPartition(
                    Socket,
                    Partition,
                    &RemoteAddress,
                    &Route))) {
            return CxPlatSocketGetLocalMtu(Socket, &Route);
        }
    }
    return 0;
}

QUIC_STATUS
QUIC_API
IceListenerCallback(
    MsQuicListener*,
    void*,
    QUIC_LISTENER_EVENT*)
{
    return QUIC_STATUS_SUCCESS;
}

struct IceAttributionContext {
    CxPlatEvent NewConnectionEvent;
    CxPlatLock Lock;
    QUIC_ADDR RemoteAddress {};
};

QUIC_STATUS
QUIC_API
IceAttributionListenerCallback(
    MsQuicListener*,
    void* Context,
    QUIC_LISTENER_EVENT* Event)
{
    if (Event->Type != QUIC_LISTENER_EVENT_NEW_CONNECTION) {
        return QUIC_STATUS_SUCCESS;
    }

    auto* AttributionContext = static_cast<IceAttributionContext*>(Context);
    {
        LockGuard LockScope{AttributionContext->Lock};
        AttributionContext->RemoteAddress =
            *Event->NEW_CONNECTION.Info->RemoteAddress;
    }
    AttributionContext->NewConnectionEvent.Set();
    return QUIC_STATUS_CONNECTION_REFUSED;
}

void
ValidateMissingCallbacks(
    HQUIC Handle,
    uint32_t Param,
    const QUIC_ICE_DATAPATH_CONFIG_V1& ValidConfig)
{
    auto Config = ValidConfig;
    Config.Receive = nullptr;
    EXPECT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SetParam(Handle, Param, sizeof(Config), &Config));

    Config = ValidConfig;
    Config.SendRelayDatagram = nullptr;
    EXPECT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SetParam(Handle, Param, sizeof(Config), &Config));

    Config = ValidConfig;
    Config.Bound = nullptr;
    EXPECT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SetParam(Handle, Param, sizeof(Config), &Config));

    Config = ValidConfig;
    Config.Unbound = nullptr;
    EXPECT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SetParam(Handle, Param, sizeof(Config), &Config));
}

void
ValidateConfigShape(
    HQUIC Handle,
    uint32_t Param,
    const QUIC_ICE_DATAPATH_CONFIG_V1& ValidConfig)
{
    EXPECT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SetParam(Handle, Param, sizeof(ValidConfig), nullptr));
    EXPECT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SetParam(
            Handle, Param, sizeof(ValidConfig) - 1, &ValidConfig));

    auto Config = ValidConfig;
    Config.Size--;
    EXPECT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SetParam(Handle, Param, sizeof(Config), &Config));

    Config = ValidConfig;
    Config.Version++;
    EXPECT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        MsQuic->SetParam(Handle, Param, sizeof(Config), &Config));

    ValidateMissingCallbacks(Handle, Param, ValidConfig);
}

void
SendIceDatagram(
    const QUIC_ADDR& RemoteAddress,
    const uint8_t* Buffer,
    uint16_t BufferLength)
{
#ifdef _WIN32
    SOCKET Socket = socket(RemoteAddress.Ip.sa_family, SOCK_DGRAM, IPPROTO_UDP);
    ASSERT_NE(INVALID_SOCKET, Socket);
#else
    int Socket = socket(RemoteAddress.Ip.sa_family, SOCK_DGRAM, IPPROTO_UDP);
    ASSERT_GE(Socket, 0);
#endif
    const int Sent =
        sendto(
            Socket,
            reinterpret_cast<const char*>(Buffer),
            BufferLength,
            0,
            &RemoteAddress.Ip,
            RemoteAddress.Ip.sa_family == AF_INET ?
                sizeof(sockaddr_in) : sizeof(sockaddr_in6));
    ASSERT_EQ(BufferLength, Sent);
#ifdef _WIN32
    closesocket(Socket);
#else
    close(Socket);
#endif
}

class IceNativeUdpReceiver {
public:
#ifdef _WIN32
    SOCKET Socket {INVALID_SOCKET};
#else
    int Socket {-1};
#endif
    QUIC_ADDR Address {};

    IceNativeUdpReceiver()
    {
        Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#ifdef _WIN32
        if (Socket == INVALID_SOCKET) {
            return;
        }
#else
        if (Socket < 0) {
            return;
        }
#endif
        sockaddr_in NativeAddress = {};
        NativeAddress.sin_family = AF_INET;
        NativeAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(
                Socket,
                reinterpret_cast<const sockaddr*>(&NativeAddress),
                sizeof(NativeAddress)) != 0) {
            Close();
            return;
        }
#ifdef _WIN32
        int AddressLength = sizeof(NativeAddress);
#else
        socklen_t AddressLength = sizeof(NativeAddress);
#endif
        if (getsockname(
                Socket,
                reinterpret_cast<sockaddr*>(&NativeAddress),
                &AddressLength) != 0) {
            Close();
            return;
        }
        CxPlatCopyMemory(&Address.Ipv4, &NativeAddress, sizeof(NativeAddress));
    }

    ~IceNativeUdpReceiver() { Close(); }

    bool IsValid() const
    {
#ifdef _WIN32
        return Socket != INVALID_SOCKET;
#else
        return Socket >= 0;
#endif
    }

    int Receive(uint8_t* Buffer, uint32_t BufferLength, uint32_t TimeoutMs)
    {
#ifdef _WIN32
        DWORD Timeout = TimeoutMs;
        if (setsockopt(
                Socket,
                SOL_SOCKET,
                SO_RCVTIMEO,
                reinterpret_cast<const char*>(&Timeout),
                sizeof(Timeout)) != 0) {
            return -1;
        }
        return recv(
            Socket,
            reinterpret_cast<char*>(Buffer),
            (int)BufferLength,
            0);
#else
        timeval Timeout = {
            (time_t)(TimeoutMs / 1000),
            (suseconds_t)((TimeoutMs % 1000) * 1000)};
        if (setsockopt(
                Socket,
                SOL_SOCKET,
                SO_RCVTIMEO,
                &Timeout,
                sizeof(Timeout)) != 0) {
            return -1;
        }
        return (int)recv(Socket, Buffer, BufferLength, 0);
#endif
    }

private:
    void Close()
    {
#ifdef _WIN32
        if (Socket != INVALID_SOCKET) {
            closesocket(Socket);
            Socket = INVALID_SOCKET;
        }
#else
        if (Socket >= 0) {
            close(Socket);
            Socket = -1;
        }
#endif
    }
};

bool
FindControlPartition(
    IceCallbackContext& Context,
    IceNativeUdpReceiver& Receiver)
{
    for (uint16_t Partition = 0;
         Partition < (uint16_t)CxPlatProcCount();
         ++Partition) {
        const QUIC_STATUS Status =
            Context.Binding.SendControl(
                Context.Binding.BindingContext,
                Partition,
                &Context.ControlRemoteAddress,
                Context.ControlBytes.data(),
                (uint32_t)Context.ControlBytes.size());
        if (QUIC_SUCCEEDED(Status)) {
            Context.ControlPartitionIndex.store(
                Partition, std::memory_order_release);
            std::array<uint8_t, 32> Received {};
            return
                Receiver.Receive(
                    Received.data(), Received.size(), 2000) ==
                (int)Context.ControlBytes.size();
        }
        EXPECT_EQ(QUIC_STATUS_NOT_SUPPORTED, Status);
    }
    return false;
}

void
SendIceDatagramAndWait(
    IceCallbackContext& Context,
    const QUIC_ADDR& RemoteAddress,
    const uint8_t* Buffer,
    uint16_t BufferLength)
{
    Context.ReceiveEvent.Reset();
    SendIceDatagram(RemoteAddress, Buffer, BufferLength);
    ASSERT_TRUE(Context.ReceiveEvent.WaitTimeout(2000));
    LockGuard LockScope{Context.ReceiveLock};
    EXPECT_EQ(BufferLength, Context.LastReceiveLength);
    ASSERT_LE(BufferLength, Context.LastReceiveBytes.size());
    EXPECT_EQ(0, memcmp(Buffer, Context.LastReceiveBytes.data(), BufferLength));
    EXPECT_EQ(QUIC_ADDRESS_FAMILY_INET, QuicAddrGetFamily(&Context.LastReceiveLocalAddress));
    EXPECT_NE(0, QuicAddrGetPort(&Context.LastReceiveLocalAddress));
    EXPECT_EQ(QUIC_ADDRESS_FAMILY_INET, QuicAddrGetFamily(&Context.LastReceiveRemoteAddress));
    EXPECT_NE(0, QuicAddrGetPort(&Context.LastReceiveRemoteAddress));
    EXPECT_LT(Context.LastReceivePartitionIndex, CxPlatProcCount());
    EXPECT_EQ(0, Context.LastReceiveTypeOfService);
}

uint64_t
GetListenerDroppedPackets(const MsQuicListener& Listener)
{
    QUIC_LISTENER_STATISTICS Stats = {};
    uint32_t StatsLength = sizeof(Stats);
    EXPECT_EQ(
        QUIC_STATUS_SUCCESS,
        MsQuic->GetParam(
            Listener.Handle,
            QUIC_PARAM_LISTENER_STATS,
            &StatsLength,
            &Stats));
    return Stats.BindingRecvDroppedPackets;
}

bool
WaitForListenerDroppedPackets(
    const MsQuicListener& Listener,
    uint64_t Expected)
{
    for (uint32_t Attempt = 0; Attempt < 2000; ++Attempt) {
        if (GetListenerDroppedPackets(Listener) == Expected) {
            return true;
        }
        CxPlatSleep(1);
    }
    return false;
}

bool
WaitForReceiveCount(
    const IceCallbackContext& Context,
    uint32_t Expected)
{
    for (uint32_t Attempt = 0; Attempt < 2000; ++Attempt) {
        if (Context.ReceiveCount.load(std::memory_order_acquire) >= Expected) {
            return true;
        }
        CxPlatSleep(1);
    }
    return false;
}

#if defined(__linux__) && defined(UDP_SEGMENT)
bool
SendIceSegmentedDatagrams(
    const QUIC_ADDR& RemoteAddress,
    const uint8_t* Buffer,
    uint16_t BufferLength,
    uint16_t SegmentLength,
    QUIC_ADDR& LocalAddress)
{
    int Socket = socket(RemoteAddress.Ip.sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (Socket < 0) {
        return false;
    }

    sockaddr_in NativeLocalAddress = {};
    NativeLocalAddress.sin_family = AF_INET;
    NativeLocalAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(
            Socket,
            reinterpret_cast<const sockaddr*>(&NativeLocalAddress),
            sizeof(NativeLocalAddress)) != 0) {
        close(Socket);
        return false;
    }

    socklen_t NativeLocalAddressLength = sizeof(NativeLocalAddress);
    const int SegmentSize = SegmentLength;
    if (getsockname(
            Socket,
            reinterpret_cast<sockaddr*>(&NativeLocalAddress),
            &NativeLocalAddressLength) != 0 ||
        setsockopt(
            Socket,
            SOL_UDP,
            UDP_SEGMENT,
            &SegmentSize,
            sizeof(SegmentSize)) != 0) {
        close(Socket);
        return false;
    }

    CxPlatCopyMemory(
        &LocalAddress.Ipv4,
        &NativeLocalAddress,
        sizeof(NativeLocalAddress));
    const int Sent =
        sendto(
            Socket,
            reinterpret_cast<const char*>(Buffer),
            BufferLength,
            0,
            &RemoteAddress.Ip,
            sizeof(sockaddr_in));
    close(Socket);
    return Sent == BufferLength;
}
#endif

} // namespace

TEST(IceDatapath, ConnectionConfigValidationAndStartedState)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());
    IceCallbackContext Context;
    MsQuicConnection Connection(Registration);
    ASSERT_TRUE(Connection.IsValid());

    auto Config = MakeIceConfig(&Context);
    ValidateConfigShape(
        Connection.Handle, QUIC_PARAM_CONN_ICE_DATAPATH_CONFIG, Config);
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Connection.SetParam(
            QUIC_PARAM_CONN_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));

    MsQuicAlpn Alpn("IceDatapath");
    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(
        Registration, Alpn, ClientCredConfig);
    ASSERT_TRUE(ClientConfiguration.IsValid());
    EXPECT_EQ(
        QUIC_STATUS_INVALID_STATE,
        Connection.Start(
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
            "127.0.0.1",
            9));
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Context.Binding.SetSelectedPath(
            Context.Binding.BindingContext, QUIC_ICE_PATH_DIRECT));
    ASSERT_TRUE(
        QUIC_SUCCEEDED(Connection.Start(
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
            "127.0.0.1",
            9)));
    ASSERT_TRUE(Context.BoundEvent.WaitTimeout(2000));
    ASSERT_EQ(1u, Context.BoundCount.load(std::memory_order_relaxed));
    ASSERT_EQ(sizeof(QUIC_ICE_BINDING_API_V1), Context.Binding.Size);
    ASSERT_EQ(QUIC_ICE_DATAPATH_VERSION_1, Context.Binding.Version);
    ASSERT_NE(nullptr, Context.Binding.BindingContext);
    ASSERT_NE(nullptr, Context.Binding.SendControl);
    ASSERT_NE(nullptr, Context.Binding.SetSelectedPath);
    EXPECT_EQ(
        QUIC_STATUS_INVALID_STATE,
        Connection.SetParam(
            QUIC_PARAM_CONN_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));
    Connection.Close();
    ASSERT_TRUE(Context.UnboundEvent.WaitTimeout(2000));
    EXPECT_EQ(1u, Context.UnboundCount.load(std::memory_order_relaxed));
}

TEST(IceDatapath, SelectedPathAppliesRelayMtuCapOnly)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());

    {
        IceCallbackContext Context;
        auto Config = MakeIceConfig(&Context);
        MsQuicConnection Connection(Registration);
        ASSERT_TRUE(Connection.IsValid());
        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            Connection.SetParam(
                QUIC_PARAM_CONN_ICE_DATAPATH_CONFIG,
                sizeof(Config),
                &Config));
        ASSERT_EQ(1500u, GetIceBindingLocalMtu(Context));
        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            Context.Binding.SetSelectedPath(
                Context.Binding.BindingContext,
                QUIC_ICE_PATH_DIRECT));
        EXPECT_EQ(1500u, GetIceBindingLocalMtu(Context));
        Connection.Close();
    }

    {
        IceCallbackContext Context;
        auto Config = MakeIceConfig(&Context);
        MsQuicConnection Connection(Registration);
        ASSERT_TRUE(Connection.IsValid());
        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            Connection.SetParam(
                QUIC_PARAM_CONN_ICE_DATAPATH_CONFIG,
                sizeof(Config),
                &Config));
        ASSERT_EQ(1500u, GetIceBindingLocalMtu(Context));
        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            Context.Binding.SetSelectedPath(
                Context.Binding.BindingContext,
                QUIC_ICE_PATH_RELAY));
        const uint16_t RelayMtu = GetIceBindingLocalMtu(Context);
        EXPECT_EQ(1400u, RelayMtu);
        EXPECT_EQ(1372u, MaxUdpPayloadSizeFromMTU(RelayMtu));
        Connection.Close();
    }
}

TEST(IceDatapath, SetSelectedPathRejectsClosingUnboundBinding)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());
    IceCallbackContext Context;
    Context.SelectPathOnUnbound = true;
    auto Config = MakeIceConfig(&Context);
    MsQuicConnection Connection(Registration);
    ASSERT_TRUE(Connection.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Connection.SetParam(
            QUIC_PARAM_CONN_ICE_DATAPATH_CONFIG,
            sizeof(Config),
            &Config));

    Connection.Close();
    ASSERT_TRUE(Context.UnboundEvent.WaitTimeout(2000));
    EXPECT_EQ(
        QUIC_STATUS_INVALID_STATE,
        Context.UnboundPathStatus.load(std::memory_order_acquire));
}

TEST(IceDatapath, BoundCallbackCanSelectDirectAndSendControl)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());
    IceNativeUdpReceiver Receiver;
    ASSERT_TRUE(Receiver.IsValid());

    IceCallbackContext Context;
    Context.SelectPathOnBound = true;
    Context.BoundPath = QUIC_ICE_PATH_DIRECT;
    Context.SendControlOnBound = true;
    Context.ControlRemoteAddress = Receiver.Address;
    auto Config = MakeIceConfig(&Context);
    MsQuicConnection Connection(Registration);
    ASSERT_TRUE(Connection.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Connection.SetParam(
            QUIC_PARAM_CONN_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));
    EXPECT_EQ(
        QUIC_STATUS_SUCCESS,
        Context.BoundPathStatus.load(std::memory_order_acquire));
    EXPECT_EQ(
        QUIC_STATUS_SUCCESS,
        Context.BoundControlStatus.load(std::memory_order_acquire));

    std::array<uint8_t, 32> Received {};
    const int ReceivedLength =
        Receiver.Receive(Received.data(), Received.size(), 2000);
    ASSERT_EQ((int)Context.ControlBytes.size(), ReceivedLength);
    EXPECT_EQ(
        0,
        memcmp(
            Context.ControlBytes.data(),
            Received.data(),
            Context.ControlBytes.size()));
    EXPECT_EQ(
        QUIC_STATUS_INVALID_STATE,
        Context.Binding.SetSelectedPath(
            Context.Binding.BindingContext, QUIC_ICE_PATH_DIRECT));
    Connection.Close();
}

TEST(IceDatapath, SelectedPathIsOneShotAndConcurrent)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());
    IceCallbackContext Context;
    auto Config = MakeIceConfig(&Context);
    MsQuicConnection Connection(Registration);
    ASSERT_TRUE(Connection.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Connection.SetParam(
            QUIC_PARAM_CONN_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));

    std::atomic<QUIC_STATUS> DirectStatus {QUIC_STATUS_ABORTED};
    std::atomic<QUIC_STATUS> RelayStatus {QUIC_STATUS_ABORTED};
    std::thread Direct([&]() {
        DirectStatus.store(
            Context.Binding.SetSelectedPath(
                Context.Binding.BindingContext, QUIC_ICE_PATH_DIRECT),
            std::memory_order_release);
    });
    std::thread Relay([&]() {
        RelayStatus.store(
            Context.Binding.SetSelectedPath(
                Context.Binding.BindingContext, QUIC_ICE_PATH_RELAY),
            std::memory_order_release);
    });
    Direct.join();
    Relay.join();
    const QUIC_STATUS First = DirectStatus.load(std::memory_order_acquire);
    const QUIC_STATUS Second = RelayStatus.load(std::memory_order_acquire);
    EXPECT_TRUE(
        (First == QUIC_STATUS_SUCCESS && Second == QUIC_STATUS_INVALID_STATE) ||
        (First == QUIC_STATUS_INVALID_STATE && Second == QUIC_STATUS_SUCCESS));
    EXPECT_EQ(
        QUIC_STATUS_INVALID_STATE,
        Context.Binding.SetSelectedPath(
            Context.Binding.BindingContext, QUIC_ICE_PATH_DIRECT));
    Connection.Close();
}

TEST(IceDatapath, ListenerRejectsRelayButCanSelectDirect)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());
    IceCallbackContext Context;
    auto Config = MakeIceConfig(&Context);
    MsQuicListener Listener(
        Registration, CleanUpManual, IceListenerCallback);
    ASSERT_TRUE(Listener.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Listener.SetParam(
            QUIC_PARAM_LISTENER_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));
    MsQuicAlpn Alpn("ListenerPathEncoding");
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Listener.Start(Alpn));
    EXPECT_EQ(
        QUIC_STATUS_NOT_SUPPORTED,
        Context.Binding.SetSelectedPath(
            Context.Binding.BindingContext, QUIC_ICE_PATH_RELAY));
    EXPECT_EQ(
        QUIC_STATUS_SUCCESS,
        Context.Binding.SetSelectedPath(
            Context.Binding.BindingContext, QUIC_ICE_PATH_DIRECT));
    Listener.Close();
}

TEST(IceDatapath, DirectPathUsesNativeUdpAndRelayPathUsesCallback)
{
    for (const QUIC_ICE_PATH_TYPE Path : {
            QUIC_ICE_PATH_DIRECT,
            QUIC_ICE_PATH_RELAY}) {
        MsQuicRegistration Registration(true);
        ASSERT_TRUE(Registration.IsValid());
        IceNativeUdpReceiver Receiver;
        ASSERT_TRUE(Receiver.IsValid());
        IceCallbackContext Context;
        auto Config = MakeIceConfig(&Context);
        MsQuicConnection Connection(Registration);
        ASSERT_TRUE(Connection.IsValid());
        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            Connection.SetParam(
                QUIC_PARAM_CONN_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));
        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            Context.Binding.SetSelectedPath(
                Context.Binding.BindingContext, Path));

        MsQuicAlpn Alpn("IceSendRouting");
        MsQuicCredentialConfig ClientCredConfig;
        MsQuicConfiguration ClientConfiguration(
            Registration, Alpn, ClientCredConfig);
        ASSERT_TRUE(ClientConfiguration.IsValid());
        ASSERT_TRUE(
            QUIC_SUCCEEDED(Connection.Start(
                ClientConfiguration,
                QUIC_ADDRESS_FAMILY_INET,
                "127.0.0.1",
                QuicAddrGetPort(&Receiver.Address))));

        std::array<uint8_t, MAX_UDP_PAYLOAD_LENGTH> Received {};
        if (Path == QUIC_ICE_PATH_DIRECT) {
            EXPECT_GT(
                Receiver.Receive(Received.data(), Received.size(), 2000),
                0);
            EXPECT_EQ(
                0u, Context.RelayCount.load(std::memory_order_acquire));
        } else if (Path == QUIC_ICE_PATH_RELAY) {
            EXPECT_TRUE(Context.RelayEvent.WaitTimeout(2000));
            EXPECT_GT(
                Context.RelayCount.load(std::memory_order_acquire), 0u);
            EXPECT_GT(
                Context.RelayBytes.load(std::memory_order_acquire), 0u);
            EXPECT_LE(
                Context.RelayMaxLength.load(std::memory_order_acquire),
                1372u);
            EXPECT_LT(
                Receiver.Receive(Received.data(), Received.size(), 100),
                0);
        }
        Connection.Close();
    }
}

TEST(IceDatapath, RelayCallbackCanReenterControlWithoutRecursion)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());
    IceNativeUdpReceiver Receiver;
    ASSERT_TRUE(Receiver.IsValid());
    IceCallbackContext Context;
    Context.ControlRemoteAddress = Receiver.Address;
    Context.ReenterControlFromRelay.store(true, std::memory_order_release);
    auto Config = MakeIceConfig(&Context);
    MsQuicConnection Connection(Registration);
    ASSERT_TRUE(Connection.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Connection.SetParam(
            QUIC_PARAM_CONN_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));
    ASSERT_TRUE(FindControlPartition(Context, Receiver));
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Context.Binding.SetSelectedPath(
            Context.Binding.BindingContext, QUIC_ICE_PATH_RELAY));

    MsQuicAlpn Alpn("RelayControlBypass");
    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(
        Registration, Alpn, ClientCredConfig);
    ASSERT_TRUE(ClientConfiguration.IsValid());
    ASSERT_TRUE(
        QUIC_SUCCEEDED(Connection.Start(
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
            "127.0.0.1",
            QuicAddrGetPort(&Receiver.Address))));
    ASSERT_TRUE(Context.RelayEvent.WaitTimeout(2000));
    EXPECT_EQ(
        QUIC_STATUS_SUCCESS,
        Context.RelayControlStatus.load(std::memory_order_acquire));
    std::array<uint8_t, 32> Received {};
    ASSERT_EQ(
        (int)Context.ControlBytes.size(),
        Receiver.Receive(Received.data(), Received.size(), 2000));
    EXPECT_EQ(1u, Context.RelayCount.load(std::memory_order_acquire));
    Connection.Close();
}

TEST(IceDatapath, RelayFailureCountsAsSendExtensionDrop)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());
    IceNativeUdpReceiver Receiver;
    ASSERT_TRUE(Receiver.IsValid());
    IceCallbackContext Context;
    Context.RelaySendStatus.store(
        QUIC_STATUS_ABORTED, std::memory_order_release);
    auto Config = MakeIceConfig(&Context);
    MsQuicConnection Connection(Registration);
    ASSERT_TRUE(Connection.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Connection.SetParam(
            QUIC_PARAM_CONN_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));
    auto* Binding =
        static_cast<QUIC_BINDING*>(Context.Binding.BindingContext);
    auto LoadCounter = [](uint64_t* Counter) {
        return (uint64_t)InterlockedCompareExchange64(
            (int64_t*)Counter, 0, 0);
    };
    const uint64_t InitialSendDrops =
        LoadCounter(&Binding->Stats.Send.ExtensionDrop);
    const uint64_t InitialRecvDrops =
        LoadCounter(&Binding->Stats.Recv.ExtensionDrop);
    ASSERT_EQ(0u, InitialSendDrops);
    ASSERT_EQ(0u, InitialRecvDrops);
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Context.Binding.SetSelectedPath(
            Context.Binding.BindingContext, QUIC_ICE_PATH_RELAY));

    MsQuicAlpn Alpn("RelaySendDropStats");
    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(
        Registration, Alpn, ClientCredConfig);
    ASSERT_TRUE(ClientConfiguration.IsValid());
    ASSERT_TRUE(
        QUIC_SUCCEEDED(Connection.Start(
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
            "127.0.0.1",
            QuicAddrGetPort(&Receiver.Address))));
    ASSERT_TRUE(Context.RelayEvent.WaitTimeout(2000));
    for (uint32_t Retry = 0;
         Retry != 100 &&
             LoadCounter(&Binding->Stats.Send.ExtensionDrop) == 0;
         ++Retry) {
        CxPlatSleep(1);
    }
    const uint64_t FinalSendDrops =
        LoadCounter(&Binding->Stats.Send.ExtensionDrop);
    const uint64_t FinalRecvDrops =
        LoadCounter(&Binding->Stats.Recv.ExtensionDrop);
    EXPECT_GT(FinalSendDrops, 0u);
    EXPECT_EQ(0u, FinalRecvDrops);
    Connection.Close();
}

TEST(IceDatapath, SendControlValidatesRouteAndClosingState)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());
    IceNativeUdpReceiver Receiver;
    ASSERT_TRUE(Receiver.IsValid());
    IceCallbackContext Context;
    Context.ControlRemoteAddress = Receiver.Address;
    auto Config = MakeIceConfig(&Context);
    MsQuicConnection Connection(Registration);
    ASSERT_TRUE(Connection.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Connection.SetParam(
            QUIC_PARAM_CONN_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));
    ASSERT_TRUE(FindControlPartition(Context, Receiver));
    const uint16_t Partition =
        Context.ControlPartitionIndex.load(std::memory_order_acquire);

    uint16_t WrongPartition = UINT16_MAX;
    for (uint16_t Candidate = 0;
         Candidate < (uint16_t)CxPlatProcCount();
         ++Candidate) {
        if (Candidate != Partition) {
            WrongPartition = Candidate;
            break;
        }
    }
    if (WrongPartition != UINT16_MAX) {
        EXPECT_EQ(
            QUIC_STATUS_NOT_SUPPORTED,
            Context.Binding.SendControl(
                Context.Binding.BindingContext,
                WrongPartition,
                &Context.ControlRemoteAddress,
                Context.ControlBytes.data(),
                (uint32_t)Context.ControlBytes.size()));
    }

    QUIC_ADDR Wildcard = {};
    QuicAddrSetFamily(&Wildcard, QUIC_ADDRESS_FAMILY_INET);
    QuicAddrSetPort(&Wildcard, 443);
    EXPECT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        Context.Binding.SendControl(
            Context.Binding.BindingContext,
            Partition,
            &Wildcard,
            Context.ControlBytes.data(),
            (uint32_t)Context.ControlBytes.size()));
    QUIC_ADDR ZeroPort = Context.ControlRemoteAddress;
    QuicAddrSetPort(&ZeroPort, 0);
    EXPECT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        Context.Binding.SendControl(
            Context.Binding.BindingContext,
            Partition,
            &ZeroPort,
            Context.ControlBytes.data(),
            (uint32_t)Context.ControlBytes.size()));
    EXPECT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        Context.Binding.SendControl(
            Context.Binding.BindingContext,
            Partition,
            &Context.ControlRemoteAddress,
            Context.ControlBytes.data(),
            0));
    std::vector<uint8_t> Oversize(MAX_UDP_PAYLOAD_LENGTH + 1, 0);
    EXPECT_EQ(
        QUIC_STATUS_INVALID_PARAMETER,
        Context.Binding.SendControl(
            Context.Binding.BindingContext,
            Partition,
            &Context.ControlRemoteAddress,
            Oversize.data(),
            (uint32_t)Oversize.size()));

    // A 1420-byte TURN Send Indication envelope remains within the
    // 1472-byte CxPlat control datagram ceiling. Relay MTU cap behavior is
    // validated independently from the binding socket.
    std::vector<uint8_t> MaxTurnEnvelope(1372 + 48, 0x55);
    ASSERT_LE(MaxTurnEnvelope.size(), (size_t)MAX_UDP_PAYLOAD_LENGTH);
    EXPECT_EQ(
        QUIC_STATUS_SUCCESS,
        Context.Binding.SendControl(
            Context.Binding.BindingContext,
            Partition,
            &Context.ControlRemoteAddress,
            MaxTurnEnvelope.data(),
            (uint32_t)MaxTurnEnvelope.size()));
    std::vector<uint8_t> Received(MaxTurnEnvelope.size());
    EXPECT_EQ(
        (int)MaxTurnEnvelope.size(),
        Receiver.Receive(Received.data(), Received.size(), 2000));

    Context.SendControlOnUnbound = true;
    Connection.Close();
    ASSERT_TRUE(Context.UnboundEvent.WaitTimeout(2000));
    EXPECT_EQ(
        QUIC_STATUS_INVALID_STATE,
        Context.UnboundControlStatus.load(std::memory_order_acquire));
}

TEST(IceDatapath, RelaySendRundownDrainsBeforeUnbound)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());
    IceNativeUdpReceiver Receiver;
    ASSERT_TRUE(Receiver.IsValid());
    IceCallbackContext Context;
    Context.BlockRelay.store(true, std::memory_order_release);
    auto Config = MakeIceConfig(&Context);
    MsQuicConnection Connection(Registration);
    ASSERT_TRUE(Connection.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Connection.SetParam(
            QUIC_PARAM_CONN_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Context.Binding.SetSelectedPath(
            Context.Binding.BindingContext, QUIC_ICE_PATH_RELAY));

    MsQuicAlpn Alpn("RelaySendRundown");
    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(
        Registration, Alpn, ClientCredConfig);
    ASSERT_TRUE(ClientConfiguration.IsValid());
    ASSERT_TRUE(
        QUIC_SUCCEEDED(Connection.Start(
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
            "127.0.0.1",
            QuicAddrGetPort(&Receiver.Address))));
    if (!Context.RelayEntered.WaitTimeout(2000)) {
        Context.AllowRelayReturn.Set();
        Connection.Close();
        ADD_FAILURE() << "relay callback did not enter";
        return;
    }

    std::thread CloseThread([&]() { Connection.Close(); });
    EXPECT_FALSE(Context.UnboundEvent.WaitTimeout(50));
    Context.AllowRelayReturn.Set();
    CloseThread.join();
    EXPECT_TRUE(Context.UnboundEvent.WaitTimeout(2000));
    EXPECT_EQ(1u, Context.UnboundCount.load(std::memory_order_acquire));
}

TEST(IceDatapath, ListenerConfigValidationAndStartedState)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());
    IceCallbackContext Context;
    MsQuicListener Listener(
        Registration, CleanUpManual, IceListenerCallback);
    ASSERT_TRUE(Listener.IsValid());

    auto Config = MakeIceConfig(&Context);
    ValidateConfigShape(
        Listener.Handle, QUIC_PARAM_LISTENER_ICE_DATAPATH_CONFIG, Config);
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Listener.SetParam(
            QUIC_PARAM_LISTENER_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));

    MsQuicAlpn Alpn("IceListener");
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Listener.Start(Alpn));
    EXPECT_EQ(
        QUIC_STATUS_INVALID_STATE,
        Listener.SetParam(
            QUIC_PARAM_LISTENER_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));
    Listener.Close();
    ASSERT_TRUE(Context.UnboundEvent.WaitTimeout(2000));
    EXPECT_EQ(1u, Context.UnboundCount.load(std::memory_order_relaxed));
}

TEST(IceDatapath, ListenerBindingLifecycleAndSharedCompatibility)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());

    IceCallbackContext Context;
    auto Config = MakeIceConfig(&Context);
    MsQuicAlpn FirstAlpn("IceFirst");
    MsQuicAlpn SecondAlpn("IceSecond");
    MsQuicAlpn ThirdAlpn("IceThird");

    MsQuicListener First(
        Registration, CleanUpManual, IceListenerCallback);
    ASSERT_TRUE(First.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        First.SetParam(
            QUIC_PARAM_LISTENER_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));
    ASSERT_EQ(QUIC_STATUS_SUCCESS, First.Start(FirstAlpn));
    ASSERT_EQ(1u, Context.BoundCount.load(std::memory_order_relaxed));
    ASSERT_EQ(sizeof(QUIC_ICE_BINDING_API_V1), Context.Binding.Size);
    ASSERT_EQ(QUIC_ICE_DATAPATH_VERSION_1, Context.Binding.Version);
    ASSERT_NE(nullptr, Context.Binding.BindingContext);
    ASSERT_NE(nullptr, Context.Binding.SendControl);
    ASSERT_NE(nullptr, Context.Binding.SetSelectedPath);

    QuicAddr BoundAddress;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, First.GetLocalAddr(BoundAddress));

    MsQuicListener Compatible(
        Registration, CleanUpManual, IceListenerCallback);
    ASSERT_TRUE(Compatible.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Compatible.SetParam(
            QUIC_PARAM_LISTENER_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Compatible.Start(SecondAlpn, &BoundAddress.SockAddr));
    EXPECT_EQ(1u, Context.BoundCount.load(std::memory_order_relaxed));

    IceCallbackContext OtherContext;
    auto IncompatibleConfig = MakeIceConfig(&OtherContext);
    MsQuicListener Incompatible(
        Registration, CleanUpManual, IceListenerCallback);
    ASSERT_TRUE(Incompatible.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Incompatible.SetParam(
            QUIC_PARAM_LISTENER_ICE_DATAPATH_CONFIG,
            sizeof(IncompatibleConfig),
            &IncompatibleConfig));
    EXPECT_EQ(
        QUIC_STATUS_INVALID_STATE,
        Incompatible.Start(ThirdAlpn, &BoundAddress.SockAddr));
    EXPECT_EQ(0u, OtherContext.BoundCount.load(std::memory_order_relaxed));

    Compatible.Close();
    EXPECT_EQ(0u, Context.UnboundCount.load(std::memory_order_relaxed));
    First.Close();
    EXPECT_EQ(1u, Context.UnboundCount.load(std::memory_order_relaxed));
}

TEST(IceDatapath, LegacyHandlesDoNotInvokeCallbacks)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());
    IceCallbackContext Context;

    MsQuicListener Listener(
        Registration, CleanUpManual, IceListenerCallback);
    ASSERT_TRUE(Listener.IsValid());
    MsQuicAlpn Alpn("LegacyIce");
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Listener.Start(Alpn));
    Listener.Close();

    MsQuicConnection Connection(Registration);
    ASSERT_TRUE(Connection.IsValid());
    EXPECT_EQ(0u, Context.BoundCount.load(std::memory_order_relaxed));
    EXPECT_EQ(0u, Context.UnboundCount.load(std::memory_order_relaxed));
}

TEST(IceDatapath, LegacySharedBindingRejectsLaterIceContext)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());

    MsQuicListener Legacy(
        Registration, CleanUpManual, IceListenerCallback);
    ASSERT_TRUE(Legacy.IsValid());
    MsQuicAlpn LegacyAlpn("LegacyFirst");
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Legacy.Start(LegacyAlpn));

    QuicAddr BoundAddress;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Legacy.GetLocalAddr(BoundAddress));

    IceCallbackContext Context;
    auto Config = MakeIceConfig(&Context);
    MsQuicListener Ice(
        Registration, CleanUpManual, IceListenerCallback);
    ASSERT_TRUE(Ice.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Ice.SetParam(
            QUIC_PARAM_LISTENER_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));
    MsQuicAlpn IceAlpn("IceSecond");
    EXPECT_EQ(
        QUIC_STATUS_INVALID_STATE,
        Ice.Start(IceAlpn, &BoundAddress.SockAddr));
    EXPECT_EQ(0u, Context.BoundCount.load(std::memory_order_relaxed));
    EXPECT_EQ(0u, Context.UnboundCount.load(std::memory_order_relaxed));
}

TEST(IceDatapath, IceSharedBindingRejectsLaterLegacyListener)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());

    IceCallbackContext Context;
    auto Config = MakeIceConfig(&Context);
    MsQuicListener Ice(
        Registration, CleanUpManual, IceListenerCallback);
    ASSERT_TRUE(Ice.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Ice.SetParam(
            QUIC_PARAM_LISTENER_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));
    MsQuicAlpn IceAlpn("IceFirst");
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Ice.Start(IceAlpn));

    QuicAddr BoundAddress;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Ice.GetLocalAddr(BoundAddress));

    MsQuicListener Legacy(
        Registration, CleanUpManual, IceListenerCallback);
    ASSERT_TRUE(Legacy.IsValid());
    MsQuicAlpn LegacyAlpn("LegacySecond");
    EXPECT_EQ(
        QUIC_STATUS_INVALID_STATE,
        Legacy.Start(LegacyAlpn, &BoundAddress.SockAddr));
    EXPECT_EQ(1u, Context.BoundCount.load(std::memory_order_relaxed));

    Ice.Close();
    ASSERT_TRUE(Context.UnboundEvent.WaitTimeout(2000));
    EXPECT_EQ(1u, Context.UnboundCount.load(std::memory_order_relaxed));
}

TEST(IceDatapath, ConnectionRejectsSharedUdpBindingInBothSetOrders)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());
    uint8_t ShareBinding = TRUE;

    IceCallbackContext ShareFirstContext;
    auto ShareFirstConfig = MakeIceConfig(&ShareFirstContext);
    MsQuicConnection ShareFirst(Registration);
    ASSERT_TRUE(ShareFirst.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        ShareFirst.SetParam(
            QUIC_PARAM_CONN_SHARE_UDP_BINDING,
            sizeof(ShareBinding),
            &ShareBinding));
    EXPECT_EQ(
        QUIC_STATUS_INVALID_STATE,
        ShareFirst.SetParam(
            QUIC_PARAM_CONN_ICE_DATAPATH_CONFIG,
            sizeof(ShareFirstConfig),
            &ShareFirstConfig));

    IceCallbackContext IceFirstContext;
    auto IceFirstConfig = MakeIceConfig(&IceFirstContext);
    MsQuicConnection IceFirst(Registration);
    ASSERT_TRUE(IceFirst.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        IceFirst.SetParam(
            QUIC_PARAM_CONN_ICE_DATAPATH_CONFIG,
            sizeof(IceFirstConfig),
            &IceFirstConfig));
    EXPECT_EQ(
        QUIC_STATUS_INVALID_STATE,
        IceFirst.SetParam(
            QUIC_PARAM_CONN_SHARE_UDP_BINDING,
            sizeof(ShareBinding),
            &ShareBinding));
}

TEST(IceDatapath, ListenerStopFromBoundKeepsBindingAlive)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());

    IceCallbackContext Context;
    auto Config = MakeIceConfig(&Context);
    MsQuicListener Listener(
        Registration, CleanUpManual, IceListenerCallback);
    ASSERT_TRUE(Listener.IsValid());
    Context.StopListenerOnBound = Listener.Handle;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Listener.SetParam(
            QUIC_PARAM_LISTENER_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));

    MsQuicAlpn Alpn("StopFromBound");
    EXPECT_EQ(QUIC_STATUS_SUCCESS, Listener.Start(Alpn));
    ASSERT_TRUE(Context.UnboundEvent.WaitTimeout(2000));
    EXPECT_EQ(1u, Context.BoundCount.load(std::memory_order_relaxed));
    EXPECT_EQ(1u, Context.UnboundCount.load(std::memory_order_relaxed));
}

TEST(IceDatapath, BlockingBoundMakesConcurrentCompatibleStartFailFast)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());

    IceCallbackContext Context;
    Context.BlockBound = true;
    auto Config = MakeIceConfig(&Context);
    MsQuicListener First(
        Registration, CleanUpManual, IceListenerCallback);
    ASSERT_TRUE(First.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        First.SetParam(
            QUIC_PARAM_LISTENER_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));

    MsQuicAlpn FirstAlpn("BlockingFirst");
    QUIC_STATUS FirstStartStatus = QUIC_STATUS_ABORTED;
    std::thread StartThread([&]() {
        FirstStartStatus = First.Start(FirstAlpn);
    });
    ASSERT_TRUE(Context.BoundEntered.WaitTimeout(2000));

    MsQuicListener Compatible(
        Registration, CleanUpManual, IceListenerCallback);
    ASSERT_TRUE(Compatible.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Compatible.SetParam(
            QUIC_PARAM_LISTENER_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));
    MsQuicAlpn CompatibleAlpn("BlockingCompatible");
    EXPECT_EQ(
        QUIC_STATUS_INVALID_STATE,
        Compatible.Start(CompatibleAlpn, &Context.LocalAddress));

    First.Stop();
    Context.AllowBoundReturn.Set();
    StartThread.join();

    EXPECT_EQ(QUIC_STATUS_SUCCESS, FirstStartStatus);
    ASSERT_TRUE(Context.UnboundEvent.WaitTimeout(2000));
    EXPECT_EQ(1u, Context.BoundCount.load(std::memory_order_relaxed));
    EXPECT_EQ(1u, Context.UnboundCount.load(std::memory_order_relaxed));
}

TEST(IceDatapath, PreparedUnconnectedClient)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());

    IceCallbackContext Context;
    auto Config = MakeIceConfig(&Context);
    MsQuicConnection Connection(Registration);
    ASSERT_TRUE(Connection.IsValid());

    QuicAddr RequestedLocal(QUIC_ADDRESS_FAMILY_INET, true);
    RequestedLocal.SetPort(0);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Connection.SetLocalAddr(RequestedLocal));
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Connection.SetParam(
            QUIC_PARAM_CONN_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));

    EXPECT_EQ(1u, Context.BoundCount.load(std::memory_order_relaxed));
    EXPECT_EQ(0u, Context.UnboundCount.load(std::memory_order_relaxed));

    QUIC_ADDR PreparedAddress = {0};
    uint32_t PreparedAddressLength = sizeof(PreparedAddress);
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Connection.GetParam(
            QUIC_PARAM_CONN_ICE_BOUND_ADDRESS,
            &PreparedAddressLength,
            &PreparedAddress));
    ASSERT_EQ(sizeof(PreparedAddress), PreparedAddressLength);
    ASSERT_NE(0, QuicAddrGetPort(&PreparedAddress));
    EXPECT_EQ(QUIC_ADDRESS_FAMILY_INET, QuicAddrGetFamily(&PreparedAddress));

    QuicAddr DifferentLocal(QUIC_ADDRESS_FAMILY_INET, true);
    DifferentLocal.SetPort(0);
    EXPECT_EQ(
        QUIC_STATUS_INVALID_STATE,
        Connection.SetLocalAddr(DifferentLocal));

    MsQuicAlpn Alpn("PreparedUnconnectedClient");
    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(
        Registration, Alpn, ClientCredConfig);
    ASSERT_TRUE(ClientConfiguration.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Context.Binding.SetSelectedPath(
            Context.Binding.BindingContext, QUIC_ICE_PATH_DIRECT));
    ASSERT_TRUE(
        QUIC_SUCCEEDED(Connection.Start(
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
            "127.0.0.1",
            9)));

    QUIC_ADDR StartedAddress = {0};
    uint32_t StartedAddressLength = sizeof(StartedAddress);
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Connection.GetParam(
            QUIC_PARAM_CONN_ICE_BOUND_ADDRESS,
            &StartedAddressLength,
            &StartedAddress));
    EXPECT_TRUE(QuicAddrCompare(&PreparedAddress, &StartedAddress));
    EXPECT_EQ(1u, Context.BoundCount.load(std::memory_order_relaxed));

    Connection.Close();
    ASSERT_TRUE(Context.UnboundEvent.WaitTimeout(2000));
    EXPECT_EQ(1u, Context.UnboundCount.load(std::memory_order_relaxed));
}

TEST(IceDatapath, PreparedUnconnectedClientCloseWithoutStart)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());

    IceCallbackContext Context;
    auto Config = MakeIceConfig(&Context);
    MsQuicConnection Connection(Registration);
    ASSERT_TRUE(Connection.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Connection.SetParam(
            QUIC_PARAM_CONN_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));
    EXPECT_EQ(1u, Context.BoundCount.load(std::memory_order_relaxed));

    Connection.Close();
    ASSERT_TRUE(Context.UnboundEvent.WaitTimeout(2000));
    EXPECT_EQ(1u, Context.UnboundCount.load(std::memory_order_relaxed));
}

TEST(IceDatapath, PreparedBindingFailureRollsBack)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());

#ifdef _WIN32
    SOCKET PortOwner = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ASSERT_NE(INVALID_SOCKET, PortOwner);
#else
    int PortOwner = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ASSERT_GE(PortOwner, 0);
#endif
    sockaddr_in NativeAddress = {0};
    NativeAddress.sin_family = AF_INET;
    NativeAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(
        0,
        bind(
            PortOwner,
            reinterpret_cast<const sockaddr*>(&NativeAddress),
            sizeof(NativeAddress)));
#ifdef _WIN32
    int NativeAddressLength = sizeof(NativeAddress);
#else
    socklen_t NativeAddressLength = sizeof(NativeAddress);
#endif
    ASSERT_EQ(
        0,
        getsockname(
            PortOwner,
            reinterpret_cast<sockaddr*>(&NativeAddress),
            &NativeAddressLength));

    QuicAddr OccupiedLocal;
    CxPlatCopyMemory(
        &OccupiedLocal.SockAddr.Ipv4,
        &NativeAddress,
        sizeof(NativeAddress));

    IceCallbackContext Context;
    auto Config = MakeIceConfig(&Context);
    MsQuicConnection Connection(Registration);
    ASSERT_TRUE(Connection.IsValid());
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Connection.SetLocalAddr(OccupiedLocal));
    EXPECT_EQ(
        QUIC_STATUS_ADDRESS_IN_USE,
        Connection.SetParam(
            QUIC_PARAM_CONN_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));
    EXPECT_EQ(0u, Context.BoundCount.load(std::memory_order_relaxed));

#ifdef _WIN32
    closesocket(PortOwner);
#else
    close(PortOwner);
#endif

    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Connection.SetParam(
            QUIC_PARAM_CONN_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));
    EXPECT_EQ(1u, Context.BoundCount.load(std::memory_order_relaxed));

    Connection.Close();
    ASSERT_TRUE(Context.UnboundEvent.WaitTimeout(2000));
    EXPECT_EQ(1u, Context.UnboundCount.load(std::memory_order_relaxed));
}

TEST(IceDatapath, ReceiveDemuxPassConsumedAndReinject)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());

    IceCallbackContext Context;
    auto Config = MakeIceConfig(&Context);
    MsQuicListener Listener(
        Registration, CleanUpManual, IceListenerCallback);
    ASSERT_TRUE(Listener.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Listener.SetParam(
            QUIC_PARAM_LISTENER_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));

    MsQuicAlpn Alpn("IceReceiveDemux");
    QuicAddr LocalAddress(QUIC_ADDRESS_FAMILY_INET, true);
    LocalAddress.SetPort(0);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Listener.Start(Alpn, &LocalAddress.SockAddr));

    uint32_t LocalAddressLength = sizeof(LocalAddress.SockAddr);
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        MsQuic->GetParam(
            Listener.Handle,
            QUIC_PARAM_LISTENER_LOCAL_ADDRESS,
            &LocalAddressLength,
            &LocalAddress.SockAddr));
    const uint64_t InitialDroppedPackets = GetListenerDroppedPackets(Listener);

    const std::array<uint8_t, 20> Stun = {
        0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x02};
    Context.Action.store(IceCallbackContext::RxAction::Consumed, std::memory_order_release);
    SendIceDatagramAndWait(Context, LocalAddress.SockAddr, Stun.data(), Stun.size());

    const std::array<uint8_t, 1> Quic = {0xC0};
    Context.Action.store(IceCallbackContext::RxAction::Pass, std::memory_order_release);
    SendIceDatagramAndWait(Context, LocalAddress.SockAddr, Quic.data(), Quic.size());
    EXPECT_TRUE(WaitForListenerDroppedPackets(Listener, InitialDroppedPackets + 1));

    const std::array<uint8_t, 5> ChannelData = {
        0x40, 0x01, 0x00, 0x01, 0xC0};
    Context.Action.store(IceCallbackContext::RxAction::Reinject, std::memory_order_release);
    SendIceDatagramAndWait(
        Context, LocalAddress.SockAddr, ChannelData.data(), ChannelData.size());
    EXPECT_TRUE(WaitForListenerDroppedPackets(Listener, InitialDroppedPackets + 2));
    {
        LockGuard LockScope{Context.ReceiveLock};
        EXPECT_FALSE(QuicAddrCompare(
            &Context.LastReceiveRemoteAddress,
            &Context.LastInnerRemoteAddress));
    }
    EXPECT_EQ(3u, Context.ReceiveCount.load(std::memory_order_relaxed));
    Listener.Close();
}

TEST(IceDatapath, ConsumedCompletesWithoutQuicPreprocess)
{
#if defined(__linux__) && defined(UDP_SEGMENT)
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());

    IceCallbackContext Context;
    auto Config = MakeIceConfig(&Context);
    MsQuicListener Listener(
        Registration, CleanUpManual, IceListenerCallback);
    ASSERT_TRUE(Listener.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Listener.SetParam(
            QUIC_PARAM_LISTENER_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));

    MsQuicAlpn Alpn("IceConsumedBarrier");
    QuicAddr LocalAddress(QUIC_ADDRESS_FAMILY_INET, true);
    LocalAddress.SetPort(0);
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Listener.Start(Alpn, &LocalAddress.SockAddr));
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Listener.GetLocalAddr(LocalAddress));
    const uint64_t InitialDroppedPackets = GetListenerDroppedPackets(Listener);

    // Both segments arrive in one UDP_GRO receive chain. QuicBindingReceive
    // cannot invoke the second callback until it has applied the first
    // callback's CONSUMED disposition, which is the production completion
    // barrier needed for the final exact dropped-packet assertion.
    const std::array<uint8_t, 10> Segments = {
        0x40, 0x01, 0x00, 0x01, 0xC0,
        0x40, 0x02, 0x00, 0x01, 0xC0};
    Context.Action.store(
        IceCallbackContext::RxAction::ConsumedFirstThenPass,
        std::memory_order_release);
    Context.BlockSecondReceive.store(true, std::memory_order_release);
    QUIC_ADDR SenderAddress = {};
    if (!SendIceSegmentedDatagrams(
            LocalAddress.SockAddr,
            Segments.data(),
            Segments.size(),
            5,
            SenderAddress)) {
        Context.AllowSecondReceiveReturn.Set();
        Listener.Close();
        GTEST_SKIP() << "UDP segmentation is unavailable";
    }

    if (!Context.SecondReceiveEntered.WaitTimeout(2000)) {
        Context.AllowSecondReceiveReturn.Set();
        Listener.Close();
        ADD_FAILURE() << "second ICE receive callback did not enter";
        return;
    }
    EXPECT_EQ(
        InitialDroppedPackets,
        GetListenerDroppedPackets(Listener));
    Context.AllowSecondReceiveReturn.Set();
    EXPECT_TRUE(WaitForListenerDroppedPackets(
        Listener, InitialDroppedPackets + 1));
    EXPECT_EQ(2u, Context.ReceiveCount.load(std::memory_order_acquire));
    Listener.Close();
#else
    GTEST_SKIP() << "UDP segmentation is unavailable";
#endif
}

TEST(IceDatapath, ReinjectDoesNotPolluteSharedGroRoute)
{
#if defined(__linux__) && defined(UDP_SEGMENT)
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());

    IceCallbackContext Context;
    auto Config = MakeIceConfig(&Context);
    MsQuicListener Listener(
        Registration, CleanUpManual, IceListenerCallback);
    ASSERT_TRUE(Listener.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Listener.SetParam(
            QUIC_PARAM_LISTENER_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));

    MsQuicAlpn Alpn("IceSharedGroRoute");
    QuicAddr ListenerAddress(QUIC_ADDRESS_FAMILY_INET, true);
    ListenerAddress.SetPort(0);
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Listener.Start(Alpn, &ListenerAddress.SockAddr));
    uint32_t ListenerAddressLength = sizeof(ListenerAddress.SockAddr);
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        MsQuic->GetParam(
            Listener.Handle,
            QUIC_PARAM_LISTENER_LOCAL_ADDRESS,
            &ListenerAddressLength,
            &ListenerAddress.SockAddr));
    const uint64_t InitialDroppedPackets = GetListenerDroppedPackets(Listener);

    // UDP_SEGMENT plus the listener's UDP_GRO option creates two recv-data
    // entries backed by one I/O block and therefore one outer route.
    const std::array<uint8_t, 10> Segments = {
        0x40, 0x01, 0x00, 0x01, 0xC0,
        0x40, 0x02, 0x00, 0x01, 0xC0};
    Context.Action.store(
        IceCallbackContext::RxAction::ReinjectFirstThenPass,
        std::memory_order_release);
    QUIC_ADDR SenderAddress = {};
    if (!SendIceSegmentedDatagrams(
            ListenerAddress.SockAddr,
            Segments.data(),
            Segments.size(),
            5,
            SenderAddress)) {
        Listener.Close();
        GTEST_SKIP() << "UDP segmentation is unavailable";
    }

    ASSERT_TRUE(WaitForReceiveCount(Context, 2));
    ASSERT_TRUE(WaitForListenerDroppedPackets(
        Listener, InitialDroppedPackets + 2));
    {
        LockGuard LockScope{Context.ReceiveLock};
        ASSERT_FALSE(QuicAddrCompare(
            &SenderAddress, &Context.LastInnerRemoteAddress));
        EXPECT_TRUE(QuicAddrCompare(
            &SenderAddress, &Context.ReceiveRemoteAddresses[0]));
        EXPECT_TRUE(QuicAddrCompare(
            &SenderAddress, &Context.ReceiveRemoteAddresses[1]));
    }
    Listener.Close();
#else
    GTEST_SKIP() << "UDP segmentation is unavailable";
#endif
}

TEST(IceDatapath, ReinjectRemoteSelectsPublicConnectionPeer)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());

    IceCallbackContext IceContext;
    IceAttributionContext AttributionContext;
    auto IceConfig = MakeIceConfig(&IceContext);
    MsQuicListener Listener(
        Registration,
        CleanUpManual,
        IceAttributionListenerCallback,
        &AttributionContext);
    ASSERT_TRUE(Listener.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Listener.SetParam(
            QUIC_PARAM_LISTENER_ICE_DATAPATH_CONFIG,
            sizeof(IceConfig),
            &IceConfig));

    MsQuicAlpn Alpn("IcePeerAttribution");
    QuicAddr ListenerAddress(QUIC_ADDRESS_FAMILY_INET, true);
    ListenerAddress.SetPort(0);
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Listener.Start(Alpn, &ListenerAddress.SockAddr));
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Listener.GetLocalAddr(ListenerAddress));

    IceContext.Action.store(
        IceCallbackContext::RxAction::ReinjectFullAlternateRemote,
        std::memory_order_release);
    MsQuicCredentialConfig ClientCredential;
    MsQuicConfiguration ClientConfiguration(
        Registration, Alpn, ClientCredential);
    ASSERT_TRUE(ClientConfiguration.IsValid());
    MsQuicConnection Client(Registration);
    ASSERT_TRUE(Client.IsValid());
    ASSERT_TRUE(QUIC_SUCCEEDED(Client.Start(
        ClientConfiguration,
        QUIC_ADDRESS_FAMILY_INET,
        "127.0.0.1",
        ListenerAddress.GetPort())));

    const bool NewConnection =
        AttributionContext.NewConnectionEvent.WaitTimeout(2000);
    if (!NewConnection) {
        ADD_FAILURE() << "new connection not attributed; receive count="
                      << IceContext.ReceiveCount.load(std::memory_order_acquire)
                      << " dropped=" << GetListenerDroppedPackets(Listener);
        Client.Close();
        Listener.Close();
        return;
    }
    ASSERT_TRUE(WaitForReceiveCount(IceContext, 1));
    {
        LockGuard IceLock{IceContext.ReceiveLock};
        LockGuard AttributionLock{AttributionContext.Lock};
        EXPECT_FALSE(QuicAddrCompare(
            &IceContext.ReceiveRemoteAddresses[0],
            &IceContext.LastInnerRemoteAddress));
        EXPECT_TRUE(QuicAddrCompare(
            &IceContext.LastInnerRemoteAddress,
            &AttributionContext.RemoteAddress));
    }

    Client.Close();
    Listener.Close();
}

TEST(IceDatapath, ReceiveDemuxFailsClosedForMalformedOutput)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());

    IceCallbackContext Context;
    auto Config = MakeIceConfig(&Context);
    MsQuicListener Listener(
        Registration, CleanUpManual, IceListenerCallback);
    ASSERT_TRUE(Listener.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Listener.SetParam(
            QUIC_PARAM_LISTENER_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));
    MsQuicAlpn Alpn("IceMalformedOutput");
    QuicAddr LocalAddress(QUIC_ADDRESS_FAMILY_INET, true);
    LocalAddress.SetPort(0);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Listener.Start(Alpn, &LocalAddress.SockAddr));
    uint32_t LocalAddressLength = sizeof(LocalAddress.SockAddr);
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        MsQuic->GetParam(
            Listener.Handle,
            QUIC_PARAM_LISTENER_LOCAL_ADDRESS,
            &LocalAddressLength,
            &LocalAddress.SockAddr));
    const uint64_t InitialDroppedPackets = GetListenerDroppedPackets(Listener);

    const std::array<uint8_t, 5> ChannelData = {
        0x40, 0x01, 0x00, 0x01, 0xC0};
    const std::array<IceCallbackContext::RxAction, 9> Actions = {
        IceCallbackContext::RxAction::MismatchedDisposition,
        IceCallbackContext::RxAction::BeforeBuffer,
        IceCallbackContext::RxAction::OutOfBounds,
        IceCallbackContext::RxAction::OverflowLength,
        IceCallbackContext::RxAction::NullInnerBuffer,
        IceCallbackContext::RxAction::EmptyInnerBuffer,
        IceCallbackContext::RxAction::WildcardRemote,
        IceCallbackContext::RxAction::ZeroPortRemote,
        IceCallbackContext::RxAction::UnknownDisposition};
    uint64_t ExpectedDroppedPackets = InitialDroppedPackets;
    for (const auto Action : Actions) {
        Context.Action.store(Action, std::memory_order_release);
        SendIceDatagramAndWait(
            Context, LocalAddress.SockAddr, ChannelData.data(), ChannelData.size());
        EXPECT_TRUE(WaitForListenerDroppedPackets(
            Listener, ++ExpectedDroppedPackets));
    }
    EXPECT_EQ(Actions.size(), Context.ReceiveCount.load(std::memory_order_relaxed));
    Listener.Close();
}

TEST(IceDatapath, ReceiveRundownDrainsBeforeUnbound)
{
    MsQuicRegistration Registration(true);
    ASSERT_TRUE(Registration.IsValid());

    IceCallbackContext Context;
    auto Config = MakeIceConfig(&Context);
    MsQuicListener Listener(
        Registration, CleanUpManual, IceListenerCallback);
    ASSERT_TRUE(Listener.IsValid());
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        Listener.SetParam(
            QUIC_PARAM_LISTENER_ICE_DATAPATH_CONFIG, sizeof(Config), &Config));
    MsQuicAlpn Alpn("IceReceiveRundown");
    QuicAddr LocalAddress(QUIC_ADDRESS_FAMILY_INET, true);
    LocalAddress.SetPort(0);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Listener.Start(Alpn, &LocalAddress.SockAddr));
    uint32_t LocalAddressLength = sizeof(LocalAddress.SockAddr);
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        MsQuic->GetParam(
            Listener.Handle,
            QUIC_PARAM_LISTENER_LOCAL_ADDRESS,
            &LocalAddressLength,
            &LocalAddress.SockAddr));

    const std::array<uint8_t, 1> Quic = {0xC0};
    Context.BlockReceive.store(true, std::memory_order_release);
    std::thread SendThread([&]() {
        SendIceDatagram(LocalAddress.SockAddr, Quic.data(), Quic.size());
    });
    const bool ReceiveEntered = Context.ReceiveEntered.WaitTimeout(2000);
    if (!ReceiveEntered) {
        Context.AllowReceiveReturn.Set();
        SendThread.join();
        Listener.Close();
        ADD_FAILURE() << "ICE receive callback did not enter";
        return;
    }

    std::thread CloseThread([&]() { Listener.Close(); });
    EXPECT_FALSE(Context.UnboundEvent.WaitTimeout(50));
    Context.AllowReceiveReturn.Set();
    SendThread.join();
    CloseThread.join();

    EXPECT_TRUE(Context.UnboundEvent.WaitTimeout(2000));
    EXPECT_EQ(1u, Context.UnboundCount.load(std::memory_order_relaxed));
}
