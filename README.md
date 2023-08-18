# RainbowBridge
RainbowBridge

微服务中承担网关Service Mesh的流量入口

## 模块
- Proxy 协议代理 http/https/tcp/udp/uds
- Gateway 网关流量的入口/出口
- Logger 日志服务器
- Mixer 流量混合扩展
- Streamer 流量统计与度量
- Metrics 统计数据可视化

服务间使用grpc通信

## 功能

接管所有
微服务与客户端
微服务与微服务
微服务与底层架的通信

兼容并实现的通信协议包括

- tcp
- uds
- redis tcp 
- http
- https
- http2
- http3
- plnack