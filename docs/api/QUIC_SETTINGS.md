QUIC_SETTINGS structure
======

The set of all customizable parameters for the library.

# Syntax

```C
typedef struct QUIC_SETTINGS {

    union {
        uint64_t IsSetFlags;
        struct {
            uint64_t MaxBytesPerKey                         : 1;
            uint64_t HandshakeIdleTimeoutMs                 : 1;
            uint64_t IdleTimeoutMs                          : 1;
            uint64_t MtuDiscoverySearchCompleteTimeoutUs    : 1;
            uint64_t TlsClientMaxSendBuffer                 : 1;
            uint64_t TlsServerMaxSendBuffer                 : 1;
            uint64_t StreamRecvWindowDefault                : 1;
            uint64_t StreamRecvBufferDefault                : 1;
            uint64_t ConnFlowControlWindow                  : 1;
            uint64_t MaxWorkerQueueDelayUs                  : 1;
            uint64_t MaxStatelessOperations                 : 1;
            uint64_t InitialWindowPackets                   : 1;
            uint64_t SendIdleTimeoutMs                      : 1;
            uint64_t InitialRttMs                           : 1;
            uint64_t MaxAckDelayMs                          : 1;
            uint64_t DisconnectTimeoutMs                    : 1;
            uint64_t KeepAliveIntervalMs                    : 1;
            uint64_t CongestionControlAlgorithm             : 1;
            uint64_t PeerBidiStreamCount                    : 1;
            uint64_t PeerUnidiStreamCount                   : 1;
            uint64_t MaxBindingStatelessOperations          : 1;
            uint64_t StatelessOperationExpirationMs         : 1;
            uint64_t MinimumMtu                             : 1;
            uint64_t MaximumMtu                             : 1;
            uint64_t SendBufferingEnabled                   : 1;
            uint64_t PacingEnabled                          : 1;
            uint64_t MigrationEnabled                       : 1;
            uint64_t DatagramReceiveEnabled                 : 1;
            uint64_t ServerResumptionLevel                  : 1;
            uint64_t MaxOperationsPerDrain                  : 1;
            uint64_t MtuDiscoveryMissingProbeCount          : 1;
            uint64_t DestCidUpdateIdleTimeoutMs             : 1;
            uint64_t GreaseQuicBitEnabled                   : 1;
            uint64_t EcnEnabled                             : 1;
            uint64_t HyStartEnabled                         : 1;
            uint64_t StreamRecvWindowBidiLocalDefault       : 1;
            uint64_t StreamRecvWindowBidiRemoteDefault      : 1;
            uint64_t StreamRecvWindowUnidiDefault           : 1;
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
            uint64_t EncryptionOffloadAllowed               : 1;
            uint64_t ReliableResetEnabled                   : 1;
            uint64_t OneWayDelayEnabled                     : 1;
            uint64_t NetStatsEventEnabled                   : 1;
            uint64_t StreamMultiReceiveEnabled              : 1;
            uint64_t XdpEnabled                             : 1;
            uint64_t QTIPEnabled                            : 1;
            uint64_t ReservedRioEnabled                     : 1;
            uint64_t MaxPacingRateBytesPerSecond            : 1;
            uint64_t MinPacingRateBytesPerSecond            : 1;
            uint64_t RESERVED                               : 16;
#else
            uint64_t RESERVED_PREVIEW                       : 8;
            uint64_t MaxPacingRateBytesPerSecond            : 1;
            uint64_t MinPacingRateBytesPerSecond            : 1;
            uint64_t RESERVED                               : 16;
#endif
        } IsSet;
    };

    uint64_t MaxBytesPerKey;
    uint64_t HandshakeIdleTimeoutMs;
    uint64_t IdleTimeoutMs;
    uint64_t MtuDiscoverySearchCompleteTimeoutUs;
    uint32_t TlsClientMaxSendBuffer;
    uint32_t TlsServerMaxSendBuffer;
    uint32_t StreamRecvWindowDefault;
    uint32_t StreamRecvBufferDefault;
    uint32_t ConnFlowControlWindow;
    uint32_t MaxWorkerQueueDelayUs;
    uint32_t MaxStatelessOperations;
    uint32_t InitialWindowPackets;
    uint32_t SendIdleTimeoutMs;
    uint32_t InitialRttMs;
    uint32_t MaxAckDelayMs;
    uint32_t DisconnectTimeoutMs;
    uint32_t KeepAliveIntervalMs;
    uint16_t CongestionControlAlgorithm; // QUIC_CONGESTION_CONTROL_ALGORITHM
    uint16_t PeerBidiStreamCount;
    uint16_t PeerUnidiStreamCount;
    uint16_t MaxBindingStatelessOperations;
    uint16_t StatelessOperationExpirationMs;
    uint16_t MinimumMtu;
    uint16_t MaximumMtu;
    uint8_t SendBufferingEnabled            : 1;
    uint8_t PacingEnabled                   : 1;
    uint8_t MigrationEnabled                : 1;
    uint8_t DatagramReceiveEnabled          : 1;
    uint8_t ServerResumptionLevel           : 2;    // QUIC_SERVER_RESUMPTION_LEVEL
    uint8_t GreaseQuicBitEnabled            : 1;
    uint8_t EcnEnabled                      : 1;
    uint8_t MaxOperationsPerDrain;
    uint8_t MtuDiscoveryMissingProbeCount;
    uint32_t DestCidUpdateIdleTimeoutMs;
    union {
        uint64_t Flags;
        struct {
            uint64_t HyStartEnabled            : 1;
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
            uint64_t EncryptionOffloadAllowed  : 1;
            uint64_t ReliableResetEnabled      : 1;
            uint64_t OneWayDelayEnabled        : 1;
            uint64_t NetStatsEventEnabled      : 1;
            uint64_t StreamMultiReceiveEnabled : 1;
            uint64_t XdpEnabled                : 1;
            uint64_t QTIPEnabled               : 1;
            uint64_t ReservedRioEnabled        : 1;
            uint64_t ReservedFlags             : 55;
#else
            uint64_t ReservedFlags             : 63;
#endif
        };
    };
    uint32_t StreamRecvWindowBidiLocalDefault;
    uint32_t StreamRecvWindowBidiRemoteDefault;
    uint32_t StreamRecvWindowUnidiDefault;
    uint64_t MaxPacingRateBytesPerSecond;
    uint64_t MinPacingRateBytesPerSecond;

} QUIC_SETTINGS;
```

# Members

`IsSetFlags`

The set of flags that indicate which other struct members are valid.

`MaxBytesPerKey`

Maximum number of bytes to encrypt with a single 1-RTT encryption key before initiating key update.

**Default value:** 274,877,906,944

`HandshakeIdleTimeoutMs`

How long a handshake can idle before it is discarded.

**Default value:** 10,000

`IdleTimeoutMs`

How long a connection can go idle before it is gracefully shut down. 0 to disable timeout.

**Default value:** 30,000

`TlsClientMaxSendBuffer`

How much client TLS data to buffer.  If the application expects large client certificates, or long client certificate chains, this value should be increased.

**Default value:** 4,096

`TlsServerMaxSendBuffer`

How much server TLS data to buffer.  If the application expects very large server certificates, or long server certificate chains, this value should be increased.

**Default value:**  8,192

`StreamRecvWindowDefault`

Initial stream receive flow control window size. This applies to all stream types. Limits for specific stream types can be set using `StreamRecvWindowBidirLocalDefault`, `StreamRecvWindowBidirRemoteDefault` and `StreamRecvWindowUnidirDefault`. The value must be a power of 2.

**Default value:** 65,536

`StreamRecvBufferDefault`

Stream initial buffer size.

**Default value:** 4,096

`ConnFlowControlWindow`

Connection-wide flow control window.

**Default value:** 16,777,216

`MaxWorkerQueueDelayUs`

The maximum queue delay (in microseconds) allowed for a worker thread. This affects loss detection and probe timeouts.

**Default value:** 250,000

`MaxStatelessOperations`

The maximum number of stateless operations that may be queued on a worker at any one time.

**Default value:** 16

`InitialWindowPackets`

The size (in packets) of the initial congestion window for a connection.

**Default value:** 10

`SendIdleTimeoutMs`

Reset congestion control after being idle `SendIdleTimeoutMs` milliseconds.

**Default value:** 1,000

`InitialRttMs`

Initial RTT estimate.

**Default value:** 333

`MaxAckDelayMs`

How long to wait after receiving data before sending an ACK. This controls batch sending ACKs, to get higher throughput with less overhead. Too long causes retransmits from the peer, too short wastefully sends ACKs.

**Default value:** 25

`DisconnectTimeoutMs`

How long to wait for an ACK before declaring a path dead and disconnecting.

**Default value:** 16,000

`KeepAliveIntervalMs`

How often to send PING frames to keep a connection alive. This also helps keep NAT table entries from expiring.

**Default value:** 0 (disabled)

`PeerBidiStreamCount`

Number of bidirectional streams to allow the peer to open. Must be non-zero to allow the peer to open any streams at all.

**Default value:** 0

`PeerUnidiStreamCount`

Number of unidirectional streams to allow the peer to open. Must be non-zero to allow the peer to open any streams at all.

**Default value:** 0

`RetryMemoryLimit`

The percentage of available memory usable for handshake connections before stateless retry is used. Calculated as `N/65535`. Global setting, not per-connection/configuration.

**Default value:** 65 (~0.1%)

`LoadBalancingMode`

 Global setting, not per-connection/configuration.

**Default value:** 0 (disabled)

`MaxOperationsPerDrain`

The maximum number of operations to drain per connection quantum.

**Default value:** 16

`SendBufferingEnabled`

Buffer send data within MsQuic instead of holding application buffers until sent data is acknowledged.

**Default value:** 1 (`TRUE`)

`PacingEnabled`

Pace sending to avoid overfilling buffers on the path.

**Default value:** 1 (`TRUE`)

`MaxPacingRateBytesPerSecond`

本连接本端 BBR sender 的最大 pacing rate，单位为 bytes/s。提供该值时应设置
对应的 `IsSet` bit（bit 46）；值为 `0` 表示禁用 soft cap。非零上限通过有界
byte credit 控制正常 ack-eliciting traffic；bootstrap datagram、ACK-only traffic
以及 congestion-control bypass/recovery traffic 仍可能形成短时突发，因此它不是
严格的 on-wire shaper。

**Default value:** 0 (disabled)

`MinPacingRateBytesPerSecond`

本连接本端 BBR sender 的最小 pacing rate，单位为 bytes/s。提供该值时应设置
对应的 `IsSet` bit（bit 47）；值为 `0` 表示禁用 soft pacing floor。该下限只提高
基于时间计算的 pacing allowance，不会提高 congestion/recovery window，不会绕过
bytes in flight、congestion control 或 flow control，也不能保证应用供数不足或链路
受限时的实际吞吐。

**Default value:** 0 (disabled)

当 `MinPacingRateBytesPerSecond` 和 `MaxPacingRateBytesPerSecond` 均非零时，min
必须小于或等于 max。`QUIC_PARAM_CONN_SETTINGS` 会先把本次设置的字段与连接当前的
另一侧边界合并，再原子校验候选 min/max；非法组合返回
`QUIC_STATUS_INVALID_PARAMETER`，原有 min/max 保持不变。单字段更新也遵循同一
规则。

两字段均可在连接启动前设置，也可通过 `QUIC_PARAM_CONN_SETTINGS` 更新已启动的
BBR 连接（started BBR connection）。更新活动 BBR 连接时，新的边界会立即刷新
pacing 状态并请求一次 send flush；修改 Configuration 仍只影响之后使用该
Configuration 的连接。

min/max 均为 per-connection、local-send、directional 设置，各端独立配置，不会
聚合多个连接，也不会配置 peer。它们只在 BBR 且 pacing enabled 时参与 pacing
计算，不会修改原始 BBR bandwidth estimator、cwnd、peer behavior 或 QUIC wire
protocol。

`MinPacingRateBytesPerSecond` 追加在 `QUIC_SETTINGS` 尾部。只包含到
`MaxPacingRateBytesPerSecond` 的旧 size 仍可按原语义 set/get max；size-aware copy
不会读取或写入 min，也不会越过调用方 buffer。

`MigrationEnabled`

Enable clients to migrate IP addresses and tuples. Requires the server to be behind a cooperative load-balancer, or behind no load-balancer.

**Default value:** 1 (`TRUE`)

`DatagramReceiveEnabled`

Advertise support for QUIC datagram extension. Both sides of a connection need to set this to `TRUE` for [DatagramSend](DatagramSend.md) to be functional and supported.

**Default value:** 0 (`FALSE`)

`ServerResumptionLevel`

Server only. Controls resumption tickets and/or 0-RTT server support. `QUIC_SERVER_RESUME_ONLY` enables sending and receiving TLS resumption tickets. The server app must call [ConnectionSendResumptionTicket](./ConnectionSendResumptionTicket.md) to send a resumption ticket to the client. `QUIC_SERVER_RESUME_AND_ZERORTT` enables sending and receiving TLS resumption tickets and generating 0-RTT keys and receiving 0-RTT payloads. The server app may decide accept/reject each 0-RTT payload individually.

**Default value:** `QUIC_SERVER_NO_RESUME` (disabled)

`MinimumMtu`

The minimum MTU supported by a connection. This will be used as the starting MTU.

**Default value:** 1248

`MaximumMtu`

The maximum MTU supported by a connection. This will be the maximum probed value.

**Default value:** 1500

`MtuDiscoverySearchCompleteTimeoutUs`

The time in microseconds to wait before reattempting MTU probing if max was not reached.

**Default value:** 600000000

`MtuDiscoveryMissingProbeCount`

The number of MTU probes to retry before exiting MTU probing.

**Default value:** 3

`MaxBindingStatelessOperations`

The maximum number of stateless operations that may be queued on a binding at any one time.

**Default value:** 100

`StatelessOperationExpirationMs`

The time limit between operations for the same endpoint, in milliseconds.

**Default value:** 100

`DestCidUpdateIdleTimeoutMs`

Idle timeout period after which the destination CID is updated before sending again.

**Default value:** 20,000

`GreaseQuicBitEnabled`

Advertise support for QUIC Grease Bit Extension. Both sides of a connection need to set this to `TRUE` for receiving and sending necessary transport parameter.

**Default value:** 0 (`FALSE`)

`EcnEnabled`

Enable sender-side ECN support. The connection will validate and react to ECN feedback from peer.

**Default value:** 0 (`FALSE`)

`StreamRecvWindowBidirLocalDefault`

Initial stream receive flow control window size for locally initiated bidirectional streams. If set, this value overwrites the `StreamRecvWindowDefault`.

**Default value:** 0 (no overwrite)

`StreamRecvWindowBidirRemoteDefault`

Initial stream receive flow control window size for remotely initiated bidirectional streams. If set, this value overwrites the `StreamRecvWindowDefault`.

**Default value:** 0 (no overwrite)

`StreamRecvWindowUnidiDefault`

Initial stream receive flow control window size for remotely initiated unidirectional streams. If set, this value overwrites the `StreamRecvWindowDefault`.

**Default value:** 0 (no overwrite)

`StreamMultiReceiveEnabled`

Enable multi receive mode. An app can continue receiving stream data without calling `StreamReceiveComplete` for each `QUIC_STREAM_EVENT_RECEIVE` indication.

**Default value:** 0 (`FALSE`)

# Remarks

When setting new values for the settings, the app must set the corresponding `.IsSet.*` parameter for each actual parameter that is being set or updated. For example:

```C
QUIC_SETTINGS Settings {0};

//
// Configures the server's idle timeout.
//
Settings.IdleTimeoutMs = 60000; // 60 seconds
Settings.IsSet.IdleTimeoutMs = TRUE;

//
// Configures the server's resumption level to allow for resumption and 0-RTT.
//
Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
Settings.IsSet.ServerResumptionLevel = TRUE;
```

# See Also

[ConfigurationOpen](ConfigurationOpen.md)<br>
[GetParam](GetParam.md)<br>
[SetParam](SetParam.md)<br>
