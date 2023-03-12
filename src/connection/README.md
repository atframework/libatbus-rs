# libatbus-connection

1. Connections should call endpoint's `acknowledge` when sent data is received by remote.
   1. For TCP, we can use ACK of TCP to trigger this call.
   2. For UDP, we can trigger this call when receive `frame_message.acknowledge`.
2. Connections should convert `StreamMessage` into `FrameMessage` according to it's MTU.
3. Virtual connections should tell node to check all related endpoint streams to check whether to resend datas when received a
   `ping` message.
4. Physical connections should tell node to destroy the conection that received a bad data.
5. Connections should allow users to force resend lost datas.
