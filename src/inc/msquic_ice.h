/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

    Private, versioned ICE datapath extension for raypx2. This header is not
    part of the stable MsQuic public ABI.

--*/

#pragma once

#include "msquic.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QUIC_ICE_DATAPATH_VERSION_1 1u

#define QUIC_PARAM_CONN_ICE_DATAPATH_CONFIG 0x0500F100u
#define QUIC_PARAM_CONN_ICE_BOUND_ADDRESS 0x0500F101u
#define QUIC_PARAM_LISTENER_ICE_DATAPATH_CONFIG 0x0400F100u

typedef enum QUIC_ICE_PATH_TYPE {
    QUIC_ICE_PATH_UNSELECTED = 0,
    QUIC_ICE_PATH_DIRECT = 1,
    QUIC_ICE_PATH_RELAY = 2
} QUIC_ICE_PATH_TYPE;

typedef enum QUIC_ICE_RX_DISPOSITION {
    QUIC_ICE_RX_PASS = 0,
    QUIC_ICE_RX_CONSUMED = 1,
    QUIC_ICE_RX_REINJECT_QUIC = 2
} QUIC_ICE_RX_DISPOSITION;

typedef struct QUIC_ICE_DATAGRAM_VIEW_V1 {
    const uint8_t* Buffer;
    uint32_t BufferLength;
    QUIC_ADDR LocalAddress;
    QUIC_ADDR RemoteAddress;
    uint16_t PartitionIndex;
    uint8_t TypeOfService;
} QUIC_ICE_DATAGRAM_VIEW_V1;

typedef struct QUIC_ICE_RX_OUTPUT_V1 {
    QUIC_ICE_RX_DISPOSITION Disposition;
    const uint8_t* InnerBuffer;
    uint32_t InnerBufferLength;
    QUIC_ADDR InnerRemoteAddress;
} QUIC_ICE_RX_OUTPUT_V1;

typedef struct QUIC_ICE_BINDING_API_V1 {
    uint32_t Size;
    uint32_t Version;
    void* BindingContext;
    QUIC_STATUS (QUIC_API *SendControl)(
        void* BindingContext,
        uint16_t PartitionIndex,
        const QUIC_ADDR* RemoteAddress,
        const uint8_t* Buffer,
        uint32_t BufferLength);
    QUIC_STATUS (QUIC_API *SetSelectedPath)(
        void* BindingContext,
        QUIC_ICE_PATH_TYPE PathType);
} QUIC_ICE_BINDING_API_V1;

typedef struct QUIC_ICE_DATAPATH_CONFIG_V1 {
    uint32_t Size;
    uint32_t Version;
    void* Context;
    QUIC_ICE_RX_DISPOSITION (QUIC_API *Receive)(
        void* Context,
        const QUIC_ICE_DATAGRAM_VIEW_V1* Input,
        QUIC_ICE_RX_OUTPUT_V1* Output);
    QUIC_STATUS (QUIC_API *SendRelayDatagram)(
        void* Context,
        const uint8_t* Buffer,
        uint32_t BufferLength);
    void (QUIC_API *Bound)(
        void* Context,
        const QUIC_ICE_BINDING_API_V1* Binding,
        const QUIC_ADDR* LocalAddress);
    void (QUIC_API *Unbound)(void* Context);
} QUIC_ICE_DATAPATH_CONFIG_V1;

#ifdef __cplusplus
}
#endif
