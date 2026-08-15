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

namespace {

struct IceCallbackContext {
    std::atomic<uint32_t> BoundCount {0};
    std::atomic<uint32_t> UnboundCount {0};
    CxPlatEvent BoundEvent;
    CxPlatEvent UnboundEvent;
    QUIC_ICE_BINDING_API_V1 Binding {};
    QUIC_ADDR LocalAddress {};
};

QUIC_ICE_RX_DISPOSITION
QUIC_API
IceReceive(
    void*,
    const QUIC_ICE_DATAGRAM_VIEW_V1*,
    QUIC_ICE_RX_OUTPUT_V1*)
{
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
