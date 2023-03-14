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
+ 服务发现
  + API控制服务发现
  + 注册到ETCD（内置）

## cargo 配置

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
+++++++++++++++++++++++++++++++
| HASH of above all(4 Bytes)  |
+++++++++++++++++++++++++++++++

```

## 服务发现

数据内容包含:

+ 节点名字（name，全局唯一）
+ 版本（version，atbus版本）
+ 业务进程自定义数据（custom_data）
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
>   + IPv6 报文头最小40字节。
> + [RFC4821](http://www.ietf.org/rfc/rfc4821.txt) 建议MTU为 1024 时应该足够安全。

