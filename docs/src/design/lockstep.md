# 针对Lockstep场景的优化

+ 逻辑帧响应、分包和重传。
  + 允许帧同步的frame_tick更加及时地发起重传。
  + 允许累计到一定数据包（临近分包边界）是立刻发送。
    + 针对延迟敏感型业务可以更加及时地响应操作。
  + 根据每个客户端地延迟综合评估逻辑帧延迟量。
+ 鉴权
  + 服务端采用Lockstep service层面的token鉴权
  + 客户端网络层鉴权使用 libatbus-rs 的基于 [服务发现](../discovery.md) 的网络层鉴权
    + 服务器创建房间时，同时分配 [服务发现](../discovery.md) 层的client的名字和Token。
  + 区分角色，服务器角色要比客户端权限更高
    + 仅服务器允许强制销毁房间、创建房间
+ UDP连接使用包冗余+向前纠错（FEC）
  + 包冗余可以通过统计丢包率动态变化。
  + 向前纠错（FEC）的帧数可以设置为当前冗余倍率/包冗余
    + 首个版本实现为按倍率冗余，即每个包发出N帧。
    + 后续版本可以增加使用XOR的冗余方式，即每N个包多发一个FEC冗余包，采用XOR恢复错误包。（每N个包允许丢失一个，同QUIC的方式）
  + 每个客户端连接单独评估倍率
  + 传统丢包重传（ARQ）延迟高
+ NACK和Reneging
  + Lockstep服务和客户端SDK实现在断线重连时使用NACK机制补包（有可能是进程退出后重启）。
  + 按需配置是否允许Reneging，如果房间支持快照，则可以允许一定程度不允许Reneging。（类似WAL机制）
+ 定时器优化
  + 针对Lockstep场景的帧率，使用简单的时间轮定时器
    + 时间轮只使用一层，1/120s为一个tick。
    + 针对1/2/3/.../30/60等可以被120整除的帧率的房间，设置 `120/帧率` 个固定定时器。
  + 对于其他帧率，使用时间轮定时器。
+ P2P加速（低优先级）。
  + 同房间玩家间可以通过类似Gossip协议的方式互传帧同步包。
  + P2P鉴权
    + 由客户端上报，服务端转发
  + 局域网加速。
    + 同子网检测。
  + UPnP/SSDP（很多路由禁用）。
  + 打洞: RFC5780 侦测NAT规则（低优先级）。
    + NAT:
      + NAT1(完全锥型（Full Cone NAT）): 内部地址(iAddr, iPort)映射到外部地址(eAddr, ePort)后，任意外部(hAddr, hPort)向(eAddr, ePort)发送的包都会转发到内部的(iAddr, iPort)
        > 此时Client 1向Server发送请求后，Server把Client 1对应的(eAddr, ePort)告知Client 2，Client 2可以直接向(eAddr, ePort)发包，最终会转给(iAddr, iPort)
      + NAT2(地址受限锥型（Restricted Cone NAT）): 内部地址(iAddr, iPort)映射到外部地址(eAddr, ePort)后，任意外部(hAddr, hPort)向(eAddr, ePort)发送的包都会转发到内部的(iAddr, iPort)。但会验证来源的hAddr必须通过内部地址(iAddr, iPort)发送过消息。
        > Client 1使用(iAddr, iPort)向Server发送请求后，Client 1需要使用相同的源地址(iAddr, iPort)给Client 2发包，然后Server把Client 1对应的(eAddr, ePort)告知Client 2。
        > Client 2后续就可以通过向(eAddr, ePort)发包最终会传达给Client 1的(iAddr, iPort)。
      + NAT3(端口受限锥型（Port Restricted Cone NAT）): 内部地址(iAddr, iPort)映射到外部地址(eAddr, ePort)后，任意外部(hAddr, hPort)向(eAddr, ePort)发送的包都会转发到内部的(iAddr, iPort)。但会验证来源的(hAddr, hPort)必须通过内部地址(iAddr, iPort)发送过消息。
        > 打洞方案同上
      + NAT4(对称型（Symmetric NAT）): 内部地址(iAddr,iPort)向外部主机(hAddr, hPort)发送数据并映射到外部地址(eAddr, ePort)后，外部主机(hAddr, hPort)向(eAddr, ePort)发送的包都会转发到内部的(iAddr, iPort)。反向无法主动发起连接。
        >
        > + 大多数Linux发行版默认firewalld规则走这种形式的NAT。
        > + 公共和企业Wifi环境使用这种方式较多。
        > + 电信运营商在逐步推行NAT4以对抗PCDN（比如河南移动在2023年实施）。
        >
+ 重要赛事冗余
  + 由Lockstep service层面分配主备，故障时切到备机。

## 关于混合使用包冗余+向前纠错（FEC）

在仅有向前纠错（FEC）的场景中，我们在游戏对局的过程中发现了偶发的玩家网络包抖动。这个时候如果仅仅有向前纠错（FEC），等到下一帧再通过纠错补偿已经会延迟一帧了。
通过网络层包冗余可以减少这种情况得抖动。

> 参考: [KCP最佳实践][1]

[1]: https://github.com/skywind3000/kcp/wiki/KCP-Best-Practice
