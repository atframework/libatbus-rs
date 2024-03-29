# 架构设计

Rust的优势:

+ 编译期生命周期分析可以找出大部分的线程安全问题内存问题。
+ 默认要求检查返回值，有利于减少程序实现BUG。
+ 对跨平台和交叉编译的支持好。
+ Cargo的包管理流程易于根据不同场景定制化和裁剪Feature。
+ 有统一完善的单元测试方案和Document方案。

Rust的劣势:

+ 生态尚欠缺，一些可靠的应用层组件还比较少。
+ 学习成本高。

## 模块化和FFI

+ 利用Rust的feature机制对包进行裁剪
  + 客户端通常不需要k8s支持，etcd支持，服务发现等等
  + 服务器在可信内网下通常不需要TLS加密
+ 现有成熟方案可以输出其他语言的接口，以便实现跨语言交互。
  + C和C++: bindgen
  + Nodejs: node-bindgen
  + ...

## 网络和数据帧封装

+ 协议和TLV
  + 对于版本号和整体长度，采用固定包头。
  + 对于网络协议的常用功能性TLV，直接采用Protobuf实现。
+ 多连接混流。
  + 每个连接可以根据自己的MTU策略来单独分包。
  + 利用 `bytes::Bytes` 的引用计数和Slice机制来避免每个连接单独分包时可能带来的内存拷贝。
  + 采用Offset和数据帧重叠来代替传统的基于Sequence的分包补包机制。
    + 由于每个连接单独分包，所以对相同数据，每个连接拆分的数据包个数和大小都是不一样的，不能使用传统的Sequence机制来补发。
    + SACK: Acknowledge包中包含 `received_max_offset`, 用于收到offset过大时提前触发重传。
    + NACK: 为了优化延迟，网络层不处理NACK，而是转为业务层按需实现。
  + 多个发送Connection优化
    + 当发现数据包已经被其他连接发送到目标了之后，可以通过RESET标记告诉该Stream要跳过已发送的数据段（offset）。
  + 合并Acknowledge包
    + 一次性收到多个包时，可以合并Acknowledge包，只发送最后一个。
  + 中继转发支持
    + Connection和(Endpoint,Stream)为M:N关系。（对于中继，可能一个连接用于转发送多个(Endpoint,Stream)对）
+ 数据包区分Stream id，用以区分不同的收发通道并实现并发。
  + 类似QUIC+HTTP/3的多Stream机制。
  + 内置Stream来处理TLS握手消息和应用指令（stop,reload以及一些业务层自定义指令）控制。
+ 数据包大小预测和标签缓存。
  + 由于protobuf的递归分析打包后数据包长度的开销可能较高，可以对不常变化的数据缓存数据内容和长度。
  + 对不常变化的数据也可以缓存以减少不必要的内存分配操作，比如 labels, options 等。
+ 实时性和带宽控制
  + 独立的IO线程以提高实时性
  + 由发送端处理带宽控制
+ 加密和鉴权
  + 1-RTT握手和0-RTT重连
    + 数据帧位于 `frame_message.packet.content` ，当启用了加密算法时此处为加密后的数据块
    + 如果数据帧存在对加密数据块的Padding， `frame_message.packet.padding_size` 指示了对齐消耗的字节数。在转换回 `packet_content` 时跳过这些数据。
    + 初始连接建立完成后，Client先向服务器发空的TLS_HANDSHAKE
  + 数据块尽可能对齐到加密算法的Block size
    + 现代化加密套件建议对齐到256bits/384bits/512bits（32/48/64字节）。
    + 对于256bits/512bits这类2的N次方的对齐，我们可以在预测包体大小时做一些优化
  + 对于匿名的Client连入，采用Token的方式鉴权，需要配合 [服务发现](../discovery.md) 先注册相应的对端名字和Token
+ 组播支持
  + 需要配合 [服务发现](../discovery.md) ，先设置分组。
  + 发送目标使用分组的名称
  + 如果存在上游中继，转给上游中继服务转发。
  + 如果不存在上游中继，自己挨个发送。
+ 多播
  + 由于每个Stream都是单独分包的，所以多播直接挨个发送即可。

关于协议层对加密和中继转发的取舍：在QUIC协议中，Stream的offset和packet number是分离的。这样的好处是分层更清晰，且对内部内容包括如何转发、如何分流的信息也是加密的。
但是这样也有个坏处，就是它的加密协商必须是基于单个连接链路的，没有解决 [HOL Blocking][3] 问题，特别是在多Stream和Relay服务混流的场景下，由于前面的包丢失会影响后面的包的Unpack，还会加剧 [HOL Blocking][3] 。
在我们的应用场景中（特别是针对帧同步服务），我们更希望多个Stream直接可以尽可能互相不影响。同时也尽量降低包重组的开销，所以这里设计为在Stream处理包乱序的问题，在packet处理层不做可靠性处理。在Stream端去做解密操作，每个Stream的密钥对单独管理。这样如果有中间人监控流量，可以获知流量是否是中继转发的、发给哪个Stream的。这会导致中间人能够探测协议类型，但是对内部具体内容还是不可见的。

### MTU和PMTUD(Path MTU Discovery)

由网络层提供建议的MTU。

+ ipv4和ipv6自适应。
  + 后续针对UDP增加MTU探测包，设置ip层不可分片，现代化硬件条件下大多数路由层不止支持576的MTU了。
+ Unix sock没有MTU，可以按照UDP的Header长度(64K)分包。
+ 共享内存通道可以根据后期需要决定是否实现，分包可以直接扩大到Message size limit。
  + 第一代libatbus的实现中，ipv6通道已经能单核跑到接近 5Gbps 和 2820K/s的QPS。业务使用上性能远远到不了这个瓶颈。
  + 第一代libatbus的实现中，单读多写的共享内存通道的压测性能约是 ipv6 的2倍。更多的优势来自于crash后不丢数据。

### 可靠UDP实现

+ 网络层仅仅提供IO抽象，可靠UDP的重传需要搭配Stream层拆包机制。
+ 不允许Reneging(同QUIC)。即只要Acknowledge收到了，就一定视为被正确接收。
  + 同上面NACK的考量，业务层处理NACK时可以实现为允许Reneging，不由网络层实现。
+ 经验值
  + RTO: 1.2/1.25倍的RTT是较优重传间隔。
  + 乱序的概率较小。
  + 网络良好时，普通用户平均0.2%的丢包率
  + 4G+Wifi大部分省延迟在50-90ms

#### 拥塞控制

考虑到我们在RUDP的典型使用场景为用户Wifi环境和4G/5G，这类网络一方面延迟抖动比较厉害（延迟高不代表拥塞），另一方面某些网络环境在高负载时会对UDP随机丢包。
传统算法中CUBIC对随机丢包不友好，BBR对延迟抖动不友好。

参考算法:

+ (大多数Linux发行版的默认) CUBIC算法: <https://datatracker.ietf.org/doc/html/rfc8312>
+ BBR算法:
  + 简要对比参考:
    + [《从 BBR 到 BBRv2》](https://zhuanlan.zhihu.com/p/580081548)
    + [《从流量控制算法谈网络优化 – 从 CUBIC 到 BBRv2 算法》](https://aws.amazon.com/cn/blogs/china/talking-about-network-optimization-from-the-flow-control-algorithm/)
  + BBR: <https://dl.acm.org/doi/pdf/10.1145/3009824>
  + BBRv2: <https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control>
  + BBR和BBRv2详细对比: <https://ieeexplore.ieee.org/abstract/document/9361674>
  + Github仓库: <https://github.com/google/bbr>
+ QUIC的拥塞控制: <https://datatracker.ietf.org/doc/html/rfc9002>
  + 和TCP的NewReno的优化相似: <https://datatracker.ietf.org/doc/html/rfc6582>

## 可观测性

可以使用 [opentelemetry][1] 的 [Rust组件][2] 来上报可观测性相关的信息。

统计项:

+ 每1/5/15/60秒
  + 上下行带宽
  + 收发包数
  + 分包Fragment数
  + 平均延迟
  + 延迟方差
  + 丢包率
  + 延迟计数:
    + 0~60ms/15ms
    + 60~180ms/30ms
    + 180~320ms/60ms
    + 320~800ms/120ms
    + 800~2000ms/300ms
    + Upper
+ 总收发包数
+ 总流量
+ 总分包Fragment数

[1]: https://opentelemetry.io/
[2]: https://crates.io/crates/opentelemetry
[3]: https://zh.wikipedia.org/wiki/%E9%98%9F%E5%A4%B4%E9%98%BB%E5%A1%9E
