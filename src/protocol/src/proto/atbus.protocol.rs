#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PacketOptions {
    /// Used to verify a untrusted endpoint
    #[prost(bytes = "bytes", optional, tag = "1")]
    pub token: ::core::option::Option<::prost::bytes::Bytes>,
}
/// =================== These codes below are helper protocols to standardize RPC and tracing frame.
/// any_value,array_value and key_value_list are just like in opentelemetry.
/// @see <https://github.com/open-telemetry/opentelemetry-proto/blob/master/opentelemetry/proto/trace/v1/trace.proto>
/// @see <https://opentelemetry.io>
/// @see <https://opentracing.io/specification/>
///
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AnyValue {
    #[prost(oneof = "any_value::Value", tags = "1, 2, 3, 4, 5, 6")]
    pub value: ::core::option::Option<any_value::Value>,
}
/// Nested message and enum types in `any_value`.
pub mod any_value {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Value {
        #[prost(string, tag = "1")]
        StringValue(::prost::alloc::string::String),
        #[prost(bool, tag = "2")]
        BoolValue(bool),
        #[prost(int64, tag = "3")]
        IntValue(i64),
        #[prost(double, tag = "4")]
        DoubleValue(f64),
        #[prost(message, tag = "5")]
        ArrayValue(super::ArrayValue),
        #[prost(message, tag = "6")]
        KvlistValue(super::KeyValueList),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ArrayValue {
    #[prost(message, repeated, tag = "1")]
    pub values: ::prost::alloc::vec::Vec<AnyValue>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyValueList {
    #[prost(map = "string, message", tag = "1")]
    pub values: ::std::collections::HashMap<::prost::alloc::string::String, AnyValue>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RpcRequest {
    #[prost(string, optional, tag = "1")]
    pub version: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, optional, tag = "2")]
    pub request_id: ::core::option::Option<i64>,
    #[prost(bytes = "bytes", optional, tag = "11")]
    pub caller: ::core::option::Option<::prost::bytes::Bytes>,
    #[prost(bytes = "bytes", optional, tag = "12")]
    pub callee: ::core::option::Option<::prost::bytes::Bytes>,
    /// RPC full name, maybe: \[DOMAIN/\]<ServiceFullName>.<MethodName>
    #[prost(string, optional, tag = "21")]
    pub rpc_name: ::core::option::Option<::prost::alloc::string::String>,
    /// Maybe: \[DOMAIN/\]<MessageFullName>, consider type_url in google.protobuf.Any.type_url
    #[prost(string, optional, tag = "22")]
    pub type_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(map = "string, bytes", tag = "31")]
    pub labels: ::std::collections::HashMap<
        ::prost::alloc::string::String,
        ::prost::bytes::Bytes,
    >,
    #[prost(map = "string, message", tag = "32")]
    pub tags: ::std::collections::HashMap<::prost::alloc::string::String, AnyValue>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RpcResponse {
    #[prost(string, optional, tag = "1")]
    pub version: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, optional, tag = "2")]
    pub request_id: ::core::option::Option<i64>,
    /// Optional response code
    #[prost(int32, optional, tag = "11")]
    pub response_code: ::core::option::Option<i32>,
    /// Optional response message
    #[prost(bytes = "bytes", optional, tag = "12")]
    pub response_message: ::core::option::Option<::prost::bytes::Bytes>,
    /// RPC full name, maybe: \[DOMAIN/\]<ServiceFullName>.<MethodName>
    #[prost(string, optional, tag = "21")]
    pub rpc_name: ::core::option::Option<::prost::alloc::string::String>,
    /// Maybe: \[DOMAIN/\]<MessageFullName>, consider type_url in google.protobuf.Any.type_url
    #[prost(string, optional, tag = "22")]
    pub type_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(map = "string, bytes", tag = "31")]
    pub labels: ::std::collections::HashMap<
        ::prost::alloc::string::String,
        ::prost::bytes::Bytes,
    >,
    #[prost(map = "string, message", tag = "32")]
    pub tags: ::std::collections::HashMap<::prost::alloc::string::String, AnyValue>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RpcStream {
    #[prost(string, optional, tag = "1")]
    pub version: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, optional, tag = "2")]
    pub request_id: ::core::option::Option<i64>,
    #[prost(string, optional, tag = "11")]
    pub caller: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "12")]
    pub callee: ::core::option::Option<::prost::alloc::string::String>,
    /// RPC full name, maybe: \[DOMAIN/\]<ServiceFullName>.<MethodName>
    #[prost(string, optional, tag = "21")]
    pub rpc_name: ::core::option::Option<::prost::alloc::string::String>,
    /// Maybe: \[DOMAIN/\]<MessageFullName>, consider type_url in google.protobuf.Any.type_url
    #[prost(string, optional, tag = "22")]
    pub type_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(map = "string, bytes", tag = "31")]
    pub labels: ::std::collections::HashMap<
        ::prost::alloc::string::String,
        ::prost::bytes::Bytes,
    >,
    #[prost(map = "string, message", tag = "32")]
    pub tags: ::std::collections::HashMap<::prost::alloc::string::String, AnyValue>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RpcTraceSpan {
    /// A unique identifier for a trace. All spans from the same trace share
    /// the same `trace_id`. The ID is a 16-byte array. An ID with all zeroes
    /// is considered invalid.
    ///
    /// This field is semantically required. Receiver should generate new
    /// random trace_id if empty or invalid trace_id was received.
    ///
    /// This field is required.
    /// @see <https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/trace/v1/trace.proto>
    /// @see <https://www.w3.org/TR/trace-context/#trace-id>
    #[prost(bytes = "bytes", optional, tag = "1")]
    pub trace_id: ::core::option::Option<::prost::bytes::Bytes>,
    /// A unique identifier for a span within a trace, assigned when the span
    /// is created. The ID is an 8-byte array. An ID with all zeroes is considered
    /// invalid.
    ///
    /// This field is semantically required. Receiver should generate new
    /// random span_id if empty or invalid span_id was received.
    ///
    /// This field is required.
    /// @see <https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/trace/v1/trace.proto>
    /// @see <https://www.w3.org/TR/trace-context/#parent-id>
    #[prost(bytes = "bytes", optional, tag = "2")]
    pub span_id: ::core::option::Option<::prost::bytes::Bytes>,
    /// trace_state conveys information about request position in multiple distributed tracing graphs.
    /// It is a trace_state in w3c-trace-context format: <https://www.w3.org/TR/trace-context/#tracestate-header>
    /// See also <https://github.com/w3c/distributed-tracing> for more details about this field.
    #[prost(string, optional, tag = "3")]
    pub trace_state: ::core::option::Option<::prost::alloc::string::String>,
    /// The `span_id` of this span's parent span. If this is a root span, then this
    /// field must be empty. The ID is an 8-byte array.
    /// @see <https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/trace/v1/trace.proto>
    /// @see <https://www.w3.org/TR/trace-context/#parent-id>
    #[prost(bytes = "bytes", optional, tag = "4")]
    pub parent_span_id: ::core::option::Option<::prost::bytes::Bytes>,
    /// start_time_unix_nano is the start time of the span. On the client side, this is the time
    /// kept by the local machine where the span execution starts. On the server side, this
    /// is the time when the server's application handler starts running.
    /// Value is UNIX Epoch time in nanoseconds since 00:00:00 UTC on 1 January 1970.
    ///
    /// This field is semantically required and it is expected that end_time >= start_time.
    #[prost(fixed64, optional, tag = "6")]
    pub start_time_unix_nano: ::core::option::Option<u64>,
    /// end_time_unix_nano is the end time of the span. On the client side, this is the time
    /// kept by the local machine where the span execution ends. On the server side, this
    /// is the time when the server application handler stops running.
    /// Value is UNIX Epoch time in nanoseconds since 00:00:00 UTC on 1 January 1970.
    ///
    /// This field is semantically required and it is expected that end_time >= start_time.
    #[prost(fixed64, optional, tag = "7")]
    pub end_time_unix_nano: ::core::option::Option<u64>,
    #[prost(map = "string, bytes", tag = "8")]
    pub labels: ::std::collections::HashMap<
        ::prost::alloc::string::String,
        ::prost::bytes::Bytes,
    >,
    #[prost(map = "string, message", tag = "9")]
    pub attributes: ::std::collections::HashMap<
        ::prost::alloc::string::String,
        AnyValue,
    >,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RpcFrame {
    #[prost(message, optional, tag = "11")]
    pub trace_span: ::core::option::Option<RpcTraceSpan>,
    #[prost(oneof = "rpc_frame::FrameType", tags = "1, 2, 3")]
    pub frame_type: ::core::option::Option<rpc_frame::FrameType>,
}
/// Nested message and enum types in `rpc_frame`.
pub mod rpc_frame {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum FrameType {
        #[prost(message, tag = "1")]
        Request(super::RpcRequest),
        #[prost(message, tag = "2")]
        Response(super::RpcResponse),
        #[prost(message, tag = "3")]
        Stream(super::RpcStream),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamAcknowledge {
    #[prost(int64, tag = "1")]
    pub stream_id: i64,
    /// All datas before this offest are received.(Not include)
    #[prost(int64, tag = "2")]
    pub acknowledge_offset: i64,
    /// Max received offest.(Not include, this is used to detect and resend lost packets)
    #[prost(int64, tag = "3")]
    pub received_max_offset: i64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PingData {
    #[prost(int64, tag = "1")]
    pub timepoint_microseconds: i64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ForwardData {
    #[prost(int32, tag = "1")]
    pub version: i32,
    #[prost(string, tag = "2")]
    pub source: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub scheme: ::prost::alloc::string::String,
    #[prost(bytes = "bytes", tag = "4")]
    pub address: ::prost::bytes::Bytes,
    #[prost(int32, tag = "5")]
    pub port: i32,
    #[prost(int64, tag = "6")]
    pub connection_id: i64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CloseReasonData {
    #[prost(enumeration = "AtbusCloseReason", tag = "1")]
    pub code: i32,
    #[prost(string, tag = "2")]
    pub message: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PacketContent {
    #[prost(message, repeated, tag = "1")]
    pub fragment: ::prost::alloc::vec::Vec<packet_content::FragmentType>,
}
/// Nested message and enum types in `packet_content`.
pub mod packet_content {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct FragmentType {
        /// @see ATBUS_INTERNAL_PACKET_TYPE
        #[prost(int32, tag = "1")]
        pub packet_type: i32,
        #[prost(bytes = "bytes", tag = "2")]
        pub data: ::prost::bytes::Bytes,
        /// @see ATBUS_PACKET_FRAGMENT_FLAG_TYPE
        #[prost(int32, tag = "3")]
        pub fragment_flag: i32,
        #[prost(message, optional, tag = "4")]
        pub options: ::core::option::Option<super::PacketOptions>,
        /// <https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set>
        /// <https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/cri-api/pkg/apis/runtime/v1/api.proto>
        ///
        /// allow custom labels
        #[prost(map = "string, string", tag = "5")]
        pub labels: ::std::collections::HashMap<
            ::prost::alloc::string::String,
            ::prost::alloc::string::String,
        >,
        /// This field should exists when first create a relay connection.
        #[prost(message, optional, tag = "6")]
        pub forward_for: ::core::option::Option<super::ForwardData>,
        /// This field only be filled when ATBUS_PACKET_FLAG_TYPE_FINISH_STREAM or ATBUS_PACKET_FLAG_TYPE_FINISH_CONNECTION is set.
        #[prost(message, optional, tag = "7")]
        pub close_reason: ::core::option::Option<super::CloseReasonData>,
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PacketData {
    /// Stream id is used for concurrency transfer.Just like Stream ID in HTTP/3
    /// We can transfer different stream on different connection to improve throughput
    #[prost(int64, tag = "1")]
    pub stream_id: i64,
    #[prost(int64, tag = "2")]
    pub stream_offset: i64,
    /// content is encoded and crypted packet_content
    #[prost(bytes = "bytes", tag = "3")]
    pub content: ::prost::bytes::Bytes,
    /// @see ATBUS_PACKET_FLAG_TYPE
    #[prost(int32, tag = "4")]
    pub flags: i32,
    /// How many datas we should ingnore for padding.
    /// It's usually used by the last package of encrypted data.
    #[prost(int32, tag = "5")]
    pub padding_size: i32,
    /// Filled by connection to detect delay
    #[prost(int64, tag = "6")]
    pub timepoint_microseconds: i64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AcknowledgeData {
    #[prost(message, optional, tag = "1")]
    pub acknowledge: ::core::option::Option<StreamAcknowledge>,
    #[prost(int64, tag = "2")]
    pub timepoint_microseconds: i64,
    /// Tell relaysvr to acknowledge forward connection,so relaysvr will not fill packet_data.forward_for
    /// for this connection any more.
    #[prost(message, optional, tag = "11")]
    pub forward_for: ::core::option::Option<ForwardData>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MessageHead {
    #[prost(string, tag = "1")]
    pub source: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub destination: ::prost::alloc::string::String,
    /// Always filled by relaysvr
    #[prost(string, tag = "3")]
    pub forward_for_source: ::prost::alloc::string::String,
    /// Always filled by relaysvr
    #[prost(int64, tag = "4")]
    pub forward_for_connection_id: i64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FrameMessage {
    #[prost(message, optional, tag = "1")]
    pub head: ::core::option::Option<MessageHead>,
    #[prost(oneof = "frame_message::Body", tags = "5, 6, 7, 8")]
    pub body: ::core::option::Option<frame_message::Body>,
}
/// Nested message and enum types in `frame_message`.
pub mod frame_message {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Body {
        #[prost(message, tag = "5")]
        Ping(super::PingData),
        #[prost(message, tag = "6")]
        Pong(super::PingData),
        #[prost(message, tag = "7")]
        Packet(super::PacketData),
        #[prost(message, tag = "8")]
        Acknowledge(super::AcknowledgeData),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum AtbusProtocolConst {
    Unknown = 0,
    /// 0x1000193
    MagicNumber = 16777619,
    Version = 3,
    /// Internal packet type, user custom type should be greater than this.
    InternalPacketType = 100,
}
impl AtbusProtocolConst {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            AtbusProtocolConst::Unknown => "ATBUS_PROTOCOL_CONST_UNKNOWN",
            AtbusProtocolConst::MagicNumber => "ATBUS_PROTOCOL_CONST_MAGIC_NUMBER",
            AtbusProtocolConst::Version => "ATBUS_PROTOCOL_CONST_VERSION",
            AtbusProtocolConst::InternalPacketType => {
                "ATBUS_PROTOCOL_CONST_INTERNAL_PACKET_TYPE"
            }
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "ATBUS_PROTOCOL_CONST_UNKNOWN" => Some(Self::Unknown),
            "ATBUS_PROTOCOL_CONST_MAGIC_NUMBER" => Some(Self::MagicNumber),
            "ATBUS_PROTOCOL_CONST_VERSION" => Some(Self::Version),
            "ATBUS_PROTOCOL_CONST_INTERNAL_PACKET_TYPE" => Some(Self::InternalPacketType),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum AtbusPacketFlagType {
    /// default value
    None = 0,
    /// Finish current stream, similar to FIN of TCP
    /// Receiver should destroy this stream when got this flag
    FinishStream = 1,
    /// Finish current connection, similar to FIN of TCP
    /// Receiver should destroy this connection when got this flag
    FinishConnection = 2,
    /// Reset offset and drop datas before offset of this packet.
    /// When endpoints are first created or receive a packet_data with acknowledge lower than the first message in queue
    /// We need to send a packet_data with ATBUS_PACKET_FLAG_RESET_OFFSET.
    /// When any packet is sent partly by this connection and the rest fragments are received by other connections, we also
    /// will send the first fragmentof next packet with ATBUS_PACKET_FLAG_TYPE_RESET_OFFSET.
    ResetOffset = 4,
    /// TLS Handshake
    TlsHandshake = 8,
}
impl AtbusPacketFlagType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            AtbusPacketFlagType::None => "ATBUS_PACKET_FLAG_TYPE_NONE",
            AtbusPacketFlagType::FinishStream => "ATBUS_PACKET_FLAG_TYPE_FINISH_STREAM",
            AtbusPacketFlagType::FinishConnection => {
                "ATBUS_PACKET_FLAG_TYPE_FINISH_CONNECTION"
            }
            AtbusPacketFlagType::ResetOffset => "ATBUS_PACKET_FLAG_TYPE_RESET_OFFSET",
            AtbusPacketFlagType::TlsHandshake => "ATBUS_PACKET_FLAG_TYPE_TLS_HANDSHAKE",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "ATBUS_PACKET_FLAG_TYPE_NONE" => Some(Self::None),
            "ATBUS_PACKET_FLAG_TYPE_FINISH_STREAM" => Some(Self::FinishStream),
            "ATBUS_PACKET_FLAG_TYPE_FINISH_CONNECTION" => Some(Self::FinishConnection),
            "ATBUS_PACKET_FLAG_TYPE_RESET_OFFSET" => Some(Self::ResetOffset),
            "ATBUS_PACKET_FLAG_TYPE_TLS_HANDSHAKE" => Some(Self::TlsHandshake),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum AtbusPacketFragmentFlagType {
    None = 0,
    /// This is not the last fragment of current packet.
    /// We need wait for more fragments to finish it.
    HasMore = 1,
}
impl AtbusPacketFragmentFlagType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            AtbusPacketFragmentFlagType::None => "ATBUS_PACKET_FRAGMENT_FLAG_TYPE_NONE",
            AtbusPacketFragmentFlagType::HasMore => {
                "ATBUS_PACKET_FRAGMENT_FLAG_TYPE_HAS_MORE"
            }
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "ATBUS_PACKET_FRAGMENT_FLAG_TYPE_NONE" => Some(Self::None),
            "ATBUS_PACKET_FRAGMENT_FLAG_TYPE_HAS_MORE" => Some(Self::HasMore),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum AtbusCloseReason {
    Unknown = 0,
    /// Shutdown by API
    Shutdown = 1,
    /// Lost connection
    PeerReset = 2,
    /// Unauthorized
    Unauthorized = 3,
}
impl AtbusCloseReason {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            AtbusCloseReason::Unknown => "ATBUS_CLOSE_REASON_UNKNOWN",
            AtbusCloseReason::Shutdown => "ATBUS_CLOSE_REASON_SHUTDOWN",
            AtbusCloseReason::PeerReset => "ATBUS_CLOSE_REASON_PEER_RESET",
            AtbusCloseReason::Unauthorized => "ATBUS_CLOSE_REASON_UNAUTHORIZED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "ATBUS_CLOSE_REASON_UNKNOWN" => Some(Self::Unknown),
            "ATBUS_CLOSE_REASON_SHUTDOWN" => Some(Self::Shutdown),
            "ATBUS_CLOSE_REASON_PEER_RESET" => Some(Self::PeerReset),
            "ATBUS_CLOSE_REASON_UNAUTHORIZED" => Some(Self::Unauthorized),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum AtbusPacketType {
    Data = 0,
    Command = 1,
    Handshake = 2,
}
impl AtbusPacketType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            AtbusPacketType::Data => "ATBUS_PACKET_TYPE_DATA",
            AtbusPacketType::Command => "ATBUS_PACKET_TYPE_COMMAND",
            AtbusPacketType::Handshake => "ATBUS_PACKET_TYPE_HANDSHAKE",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "ATBUS_PACKET_TYPE_DATA" => Some(Self::Data),
            "ATBUS_PACKET_TYPE_COMMAND" => Some(Self::Command),
            "ATBUS_PACKET_TYPE_HANDSHAKE" => Some(Self::Handshake),
            _ => None,
        }
    }
}
