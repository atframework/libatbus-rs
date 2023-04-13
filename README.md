# libatbus-rs

下一代libatbus通信层中间件。

设计目标:

+ 支持云原生，支持中继。
  + 不再强制要求树形结构。
  + 单独的中继服务。
  + 采用按标签的服务发现来管理中继和连接，节点根据不同的域来决定是否连接上级中继和采用哪一些连接。
    + 对于同namespace的节点，可以连接内部地址。
    + 对于跨namespace的节点，可以连接流量入口的ingress/service地址。
    + 对于中继连接的选择，可配置优先通过自己的上级中继中转还是直接对方的中继服务代理。
+ 支持多连接混流。
+ 支持0-RTT/1-RTT鉴权。
+ 支持匿名连接。
+ 支持对不可信网络动态分配Token和节点名称。
+ 支持低延迟控制。
+ 服务发现
  + API控制服务发现
  + 注册到ETCD（内置）


## For Developer

### cargo 配置

File path `~/.cargo/config.toml` or `~/.cargo/config`

```toml

[cargo-new]
name = "Your Name"        # name to use in `authors` field
email = "you@example.com" # email address to use in `authors` field
vcs = "none"              # VCS to use ('git', 'hg', 'pijul', 'fossil', 'none')

[http]
debug = false               # HTTP debugging
proxy = "host:port"         # HTTP proxy in libcurl format
ssl-version = "tlsv1.3"     # TLS version to use
ssl-version.max = "tlsv1.3" # maximum TLS version
ssl-version.min = "tlsv1.1" # minimum TLS version
timeout = 30                # timeout for each HTTP request, in seconds
low-speed-limit = 10        # network timeout threshold (bytes/sec)
cainfo = "cert.pem"         # path to Certificate Authority (CA) bundle
check-revoke = true         # check for SSL certificate revocation
multiplexing = true         # HTTP/2 multiplexing
user-agent = "…"            # the user-agent header

[net]
retry = 2                   # network retries
git-fetch-with-cli = true   # use the `git` executable for git operations
offline = false             # do not access the network

[registries.<name>]  # registries other than crates.io
index = "…"          # URL of the registry index
token = "…"          # authentication token for the registry

[registry]
default = "…"        # name of the default registry
token = "…"          # authentication token for crates.io

[source.<name>]      # source definition and replacement
replace-with = "…"   # replace this source with the given named source
directory = "…"      # path to a directory source
registry = "…"       # URL to a registry source
local-registry = "…" # path to a local registry source
git = "…"            # URL of a git repository source
branch = "…"         # branch name for the git repository
tag = "…"            # tag name for the git repository
rev = "…"            # revision for the git repository


```

https://doc.rust-lang.org/cargo/reference/config.html

### 压力测试

```bash

# 关闭对比报告
cargo install cargo-criterion

cargo criterion --plotting-backend disabled -- --discard-baseline
```

## Protocol

```

+++++++++++++++++++++++++++++++
|     TCP/UDP/... Headers     |
+++++++++++++++++++++++++++++++
|       Package Headers       |
+-----------------------------+
|      varint ->  Version     |
+-----------------------------+
|      varint ->  Length      |
+-----------------------------+
|    frame_message(Length)    |
+-----------------------------+
| HASH of above all(4 Bytes)  |
+++++++++++++++++++++++++++++++

```

frame_message的部分由 `libatbus_protocol.proto` 定义下一级消息结构。
混流和多stream并发参考了QUIC和HTTP/3的一些设计，主要内容如下(为了适应跨语言和某些框架不支持无符号数，我们全部使用有符号数字):

```protobuf
// 公共消息头
message message_head {
  // 发送来源名称
  string source = 1;

  // 发送目标服务名
  string destination = 2;

  // 由中继服务填充，指示为谁转发
  string forward_for_source = 3;

  // 由中继服务填充，指示转发的连接，方便下级节点查询连接的ip、端口等。
  int64 forward_for_connection_id = 4;
}

// 消息体
message frame_message {
  message_head head = 1;
  oneof        body {
    // ping/pong用于定期测试连接的延迟，每个连接单独处理
    ping_data        ping   = 5;
    ping_data        pong   = 6;
    packet_data      packet      = 7;
    acknowledge_data acknowledge = 8;
  }
}

// 每个连接单独acknowledge
message stream_acknowledge {
  // 每个stream单独记接收通道，这样对于不同类型的消息可以互不影响接收。
  int64 stream_id = 1;

  // stream已经全部收到的消息序号
  // 每个流可能重复收到多个acknowledge，已最大的为准。
  int64 acknowledge_offset = 2;

  // stream已经收到的最大消息序号
  // 每个流可能重复收到多个acknowledge，已最大的为准。
  // 如果acknowledge_offset和received_max_offset差异过大，我们基本上可以认为大概率发生了丢包，可以立即补发。
  int64 received_max_offset = 3;
}

message packet_data {
  // Stream id is used for concurrency transfer.Just like Stream ID in HTTP/3
  // We can transfer different stream on different connection to improve throughput
  int64 stream_id     = 1;
  int64 stream_offset = 2;

  // 数据包内容。详细数据类型见 packet_content。
  // 对于TLS握手阶段，这里的数据未加密未压缩，此时 flags 中打 ATBUS_PACKET_FLAG_TYPE_TLS_HANDSHAKE 标记。packet_type为 ATBUS_PACKET_TYPE_HANDSHAKE 。
  // 对于数据传输阶段，这个内容可能被加密或压缩，取决于配置。
  bytes content = 3;

  // 包标签，只是是否断开连接、流，是否握手包等等。
  // 对于混流时，如果一个流的神域数据不需要再被发送，数据包可以通过打ATBUS_PACKET_FLAG_TYPE_RESET_OFFSET标记忽略先前的包。
  int32 flags = 4;

  // 指示收到的数据中，有多少是由于对齐操作产生，不实际参与解包操作。
  // 这通常在存在加密套件时有用。
  int32 padding_size = 5;

  // 这个消息用于回带在acknowledge中，实时检测连接延迟。
  int64 timepoint_microseconds = 6;
}

message packet_content {
  message fragment_type {
    // 包类型，默认0为数据包，这样最大可能出现的包没有网络开销。
    int32 packet_type = 1;

    // 实际数据。
    bytes data        = 2;

    // 包含标记位指示是否有后续包，如果没有表示没有被分包或者这是分包的最后一个包。
    // 此处类似于websocket的final fragment标记。
    int32 fragment_flag = 3;

    // 自定义选项，比如对于某些客户端鉴权流程中，里面可以包含token信息。
    packet_options options = 4;

    // 数据包标签，类似k8s的流量标签，仅第一个包需要传该值。
    // https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set
    // https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/cri-api/pkg/apis/runtime/v1/api.proto
    map<string, string> labels = 5; // allow custom labels

    // 转发来源信息，由relay服务填充。
    // 当建立连接收到对端的acknowledge后，就不再需要填充这个信息。
    forward_data forward_for = 6;

    // 如果是关闭消息，这里包含关闭原因。
    close_reason_data close_reason = 7;
  }

  // 每个数据帧可能包含多个数据片段，有可能包含上一个packet的最后一个fragment和下一个packet的第一个fragment
  repeated fragment_type fragment = 1;
}
```

对于接收端，由于存在混流，可能出现包重叠的情况。对于这种情况，如果接收的包存在包含关系，我们只需要保留大的那个即可。
如果接收的包是重叠关系，我们在提取数据的时候截止到 `ATBUS_PACKET_FRAGMENT_FLAG_TYPE_HAS_MORE` 标记不存在后。之前的数据块都可以直接丢弃。
对于Connection存在过多的未提取数据时，我们先暂存一个数据包，然后对于UDP连接直接丢弃数据，对于TCP连接需要把连接排除Polling，并等待数据被取走后重新加入Polling。

对于发送端，Stream里保存上层传入的原始待发送数据，每个连接层再根据自己的设置（主要是MTU）分包。每个连接每次收到acknowledge和ping包后要检查等待acknowledge的发送时间，来判定是否可能丢包了需要补包。对于发送队列满的情况（有过多的未确认数据），需要返回WouldBlock，并记录上游的Stream，在后续收到 acknowledge 后转为可写，继续传输数据。

## 服务发现

数据内容包含:

+ 节点名字（name，全局唯一）
+ 版本（version，atbus版本）
+ 业务进程自定义数据（custom_data）
+ 鉴权信息（token，列表）
+ 主机信息（host）
  + 主机名/IP（hostname，用于判定是否跨机器（Unix Socket仅本机可达））
  + 进程ID（pid，用于判定是否跨进程（直接内存访问仅同进程可达））
+ 微服务元数据（metadata）
  + 命名空间（namespace_name）
  + 业务API版本（api_version）
  + 业务类型（kind）
  + 业务分组（group）
  + Key-Value标签（labels，同 https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set ）
  + Key-Value声明（annotations，同 https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/ ）
+ 入口网关（gateway，多个）
  + 优先级（priority）
  + 地址（address，格式为"协议://IP或域名:端口"，可多个）
  + 匹配要求（match）
    + 主机信息（host，可选，无则不限制）...
    + 微服务元数据（metadata，可选，无则不限制,map元素匹配子集即可）...
+ 推荐中继服务（advertise_relay）
  + 节点名字（name，可选）
  + 微服务元数据（metadata，可选）

备注:

1. 同机器判定应为 `metadata.namespace_name` 和 `host.hostname` 均相同
2. 同进程判定应为 `metadata.namespace_name` ， `host.hostname` 和 `host.pid` 均相同
3. 名字规则建议遵循K8s规范 https://kubernetes.io/docs/concepts/overview/working-with-objects/names/
4. 对于客户端（不可信网络）场景，需要由服务器接口分配 `source` 、`stream_id` 和 `token` ，客户端（不可信网络）连入时验证 `source` 和`stream_id` 对应的 `token` 。

## 语义转换建议

语义转换通常用于 **Key-Value标签（labels）** 和 **Key-Value声明（annotations）** 中。

| 用于   | Key             |
| ------ | --------------- |
| 区域   | `area.region`   |
| 地区   | `area.district` |
| 大区ID | `area.zone_id`  |

## Tips

+ 为什么不把RUDP协议和Stream分片管理分离？

RUDP的大部分逻辑和Stream分片管理是重合的。我们考虑到后面可能用于帧同步服务,而由于 [RFC 791](http://www.ietf.org/rfc/rfc791.txt) 规定所有设备的接受IPv4报文的长度至少要大于576。
除去IPv4包头的20字接和UDP包头的8字节。剩下要保证可达性，比较简单的方法是让包的正文小于548字节。这时候单单解耦而为相似功能而增加一批包头就显得很不合算了。

> + [RFC2460](https://www.ietf.org/rfc/rfc2460.txt) 指示IPv6的最小MTU为 1280。
>   + IPv6 报文头最小40字节，还要除去8字节fragment头，无扩展选项是最小可用1232字节（如果再除去UDP的8字节头剩余1224字节）。
> + [RFC4821](http://www.ietf.org/rfc/rfc4821.txt) 建议MTU为 1024 时应该足够安全。

