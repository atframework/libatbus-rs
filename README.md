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

## cargo 配置

File path ```~/.cargo/config.toml``` or ```~/.cargo/config```

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

## Tips

+ 为什么不把RUDP协议和Stream分片管理分离？

RUDP的大部分逻辑和Stream分片管理是重合的。我们考虑到后面可能用于帧同步服务,而由于RFC 791规定所有设备的接受IPv4报文的长度至少要大于576。
除去IPv4包头的20字接和UDP包头的8字节。剩下要保证可达性，比较简单的方法是让包的正文小于548字节。这时候单单解耦而为相似功能而增加一批包头就显得很不合算了。
