# libatbus-rs 文档

下一代libatbus通信层中间件。

## 设计目标

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

+ [Cargo配置参考](developer/cargo-configure.md)

## Protocol

+ [libatbus协议](protocol/libatbus-rs.md)
+ [其他协议参考](protocol/reference.md)

## 服务发现

+ [其他协议参考](discovery.md)
