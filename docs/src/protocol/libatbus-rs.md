# libatbus-rs 协议

## 底层协议（版本从3开始）

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

流控: 类似QUIC协议，由发送端控制，接收端超出流控直接丢弃。
