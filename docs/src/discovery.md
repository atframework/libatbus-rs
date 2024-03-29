# 服务发现

数据内容包含两种类型： **节点和分组**

## 节点类型

+ 节点名字（name，全局唯一）
+ 类型（type=node|client）
+ 版本（version，atbus版本）
+ HashCode（hash_code，HashCode缓存，用于一致性Hash计算）
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
  + Key-Value标签（labels，同 <https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set> ）
+ 入口网关（gateway，多个。同一个地址也可以配置多条，匹配要求不同）
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
3. 名字规则建议遵循K8s规范 <https://kubernetes.io/docs/concepts/overview/working-with-objects/names/>
4. 对于客户端（不可信网络）场景，需要由服务器接口分配 `source` 、`stream_id` 和 `token` ，客户端（不可信网络）连入时验证 `source` 和`stream_id` 对应的 `token` 。
5. 对于中继服务是集群的情况，在选取可用的中继服务时，**节点名字** 参与一致性Hash计算，以获取相对稳定的节点路由。
6. 客户端模式（type=client）

  + 当节点是客户端类型（type=client）时，不能主动发起连接，而是总是选择收到包来源的中继或Connection作为发送目标。

## 分组类型

+ 节点名字（name，全局唯一）
+ 类型（type=group）
+ 版本（version，atbus版本）
+ 业务进程自定义数据（custom_data）
+ 节点列表（node_list，多个）
  + 节点名字（node_name）
