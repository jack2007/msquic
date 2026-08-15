/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "precomp.h"
#undef min
#undef max
#include "gtest/gtest.h"
#include "msquic_ice.h"

#include <atomic>
#include <array>
#include <cstdint>
#include <thread>

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
        UnknownDisposition
    };
    std::atomic<RxAction> Action {RxAction::Pass};
    std::atomic<uint32_t> ReceiveCount {0};
    CxPlatEvent ReceiveEvent;
    CxPlatEvent ReceiveEntered;
    CxPlatEvent AllowReceiveReturn;
    std::atomic<bool> BlockReceive {false};
    CxPlatLock ReceiveLock;
    uint32_t LastReceiveLength {0};
    std::array<uint8_t, 24> LastReceiveBytes {};
    QUIC_ADDR LastReceiveLocalAddress {};
    QUIC_ADDR LastReceiveRemoteAddress {};
    uint16_t LastReceivePartitionIndex {0};
    uint8_t LastReceiveTypeOfService {0};
};

QUIC_ICE_RX_DISPOSITION
QUIC_API
IceReceive(
    void* Context,
    const QUIC_ICE_DATAGRAM_VIEW_V1* Input,
    QUIC_ICE_RX_OUTPUT_V1* Output)
{
    auto* CallbackContext = static_cast<IceCallbackContext*>(Context);
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
        CallbackContext->LastReceivePartitionIndex = Input->PartitionIndex;
        CallbackContext->LastReceiveTypeOfService = Input->TypeOfService;
    }
    CallbackContext->ReceiveCount.fetch_add(1, std::memory_order_relaxed);
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
        Output->InnerRemoteAddress = Input->RemoteAddress;
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
    }

    return QUIC_ICE_RX_PASS;
}

QUIC_STATUS
QUIC_API
IceSendRelayDatagram(
    void*,
    const uint8_t*,
    uint32_t)
{
    return QUIC_STATUS_SUCCESS;
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

QUIC_STATUS
QUIC_API
IceListenerCallback(
    MsQuicListener*,
    void*,
    QUIC_LISTENER_EVENT*)
{
    return QUIC_STATUS_SUCCESS;
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
    ASSERT_TRUE(WaitForListenerDroppedPackets(Listener, InitialDroppedPackets));

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
    EXPECT_EQ(3u, Context.ReceiveCount.load(std::memory_order_relaxed));
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
