# RainbowBridge

🌈 **RainbowBridge** - 高性能微服务网关，承担Service Mesh的流量入口

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](#)

## 🚀 项目简介

RainbowBridge是一个基于Golang和Gin框架开发的高性能网关服务，专为微服务架构设计。它提供了完整的流量管理、协议转换、负载均衡、监控统计等功能，是现代微服务架构中不可或缺的基础设施组件。

## 📋 核心模块

### 🔧 Server (服务器模块)
- 支持HTTP、HTTPS、TCP、UDP、UDS多协议服务器
- 高并发连接处理
- 灵活的TLS配置
- HTTP/2支持

### 🔄 Proxy (协议代理模块)
- HTTP/HTTPS代理
- TCP/UDP代理
- gRPC代理
- Unix Domain Socket代理
- 智能负载均衡
- 健康检查

### 🌐 Gateway (网关模块)
- 域名路由分发
- SNI支持
- 多证书管理
- 路由规则引擎
- 中间件链

### 📝 Logger (日志模块)
- 基于Zap的高性能日志
- 结构化日志输出
- 日志轮转和压缩
- 多级别日志控制

### 🔀 Mixer (流量混合模块)
- 协议转换(HTTP↔gRPC、HTTP↔TCP)
- WebSocket升级
- 流量路由
- 协议适配

### 📊 Streamer (流量统计模块)
- InfluxDB集成
- 实时流量监控
- HTTP/gRPC API
- 性能指标收集

## ✨ 核心功能

### 🔐 安全特性
- ✅ 多域名SSL证书支持
- ✅ SNI (Server Name Indication)
- ✅ TLS 1.2/1.3支持
- ✅ 自动HTTPS重定向
- ✅ 安全头部设置

### 🚦 流量管理
- ✅ 智能负载均衡(轮询、最少连接、权重)
- ✅ 健康检查
- ✅ 限流控制
- ✅ 熔断保护
- ✅ 重试机制
- ✅ 请求体大小限制

### 🔄 协议支持
- ✅ HTTP/1.1 & HTTP/2
- ✅ WebSocket
- ✅ gRPC
- ✅ TCP/UDP
- ✅ Unix Domain Socket

### 📈 监控统计
- ✅ 实时流量统计
- ✅ InfluxDB时序数据存储
- ✅ 请求追踪(Trace ID)
- ✅ 性能指标监控
- ✅ RESTful API接口

### 🛠️ 运维特性
- ✅ 热配置重载
- ✅ 优雅关闭
- ✅ 健康检查端点
- ✅ 详细的访问日志
- ✅ 错误处理中间件

## 🏗️ 架构设计

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client        │    │   RainbowBridge │    │   Backend       │
│                 │    │                 │    │   Services      │
│  ┌───────────┐  │    │  ┌───────────┐  │    │  ┌───────────┐  │
│  │  Browser  │  │────┤  │  Gateway  │  │────┤  │  Service1 │  │
│  └───────────┘  │    │  └───────────┘  │    │  └───────────┘  │
│                 │    │        │        │    │                 │
│  ┌───────────┐  │    │  ┌───────────┐  │    │  ┌───────────┐  │
│  │   App     │  │────┤  │   Proxy   │  │────┤  │  Service2 │  │
│  └───────────┘  │    │  └───────────┘  │    │  └───────────┘  │
│                 │    │        │        │    │                 │
│  ┌───────────┐  │    │  ┌───────────┐  │    │  ┌───────────┐  │
│  │   gRPC    │  │────┤  │   Mixer   │  │────┤  │  Service3 │  │
│  └───────────┘  │    │  └───────────┘  │    │  └───────────┘  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                       ┌─────────────────┐
                       │   Streamer      │
                       │   (Metrics)     │
                       └─────────────────┘
                              │
                       ┌─────────────────┐
                       │   InfluxDB      │
                       │   (Storage)     │
                       └─────────────────┘
```

## 🚀 快速开始

### 环境要求

- Go 1.21+
- InfluxDB 2.0+ (可选，用于流量统计)

### 安装步骤

1. **克隆项目**
```bash
git clone https://github.com/landers1037/RainbowBridge.git
cd RainbowBridge
```

2. **安装依赖**
```bash
go mod download
```

3. **编译项目**
```bash
go build -o rainbowbridge cmd/rainbowbridge/main.go
```

4. **准备配置文件**
```bash
cp configs/rainbowbridge.toml configs/production.toml
# 编辑配置文件
```

5. **启动服务**
```bash
./rainbowbridge -config configs/production.toml
```

### Docker部署

```bash
# 构建镜像
docker build -t rainbowbridge:latest .

# 运行容器
docker run -d \
  --name rainbowbridge \
  -p 80:80 \
  -p 443:443 \
  -p 8080:8080 \
  -v $(pwd)/configs:/app/configs \
  -v $(pwd)/certs:/app/certs \
  rainbowbridge:latest
```

## ⚙️ 配置说明

### 基础配置

```toml
# 全局配置
debug = false
logLevel = "INFO"
InsecureSkipVerify = true
defaultEntryPoints = ["http", "https"]

# 入口点配置
[entryPoints]
  [entryPoints.http]
    address = ":80"
  [entryPoints.https]
    address = ":443"
```

### 路由配置

```toml
[http.routers.api]
  entryPoints = ["https"]
  rule = "Host(`api.example.com`)"
  middlewares = ["compress", "rateLimit", "trace"]
  tls = true
  service = "api-service"
```

### 服务配置

```toml
[http.services.api-service]
  [http.services.api-service.loadBalancer]
    [[http.services.api-service.loadBalancer.servers]]
      url = "http://localhost:9000"
      weight = 1
    [http.services.api-service.loadBalancer.healthCheck]
      path = "/health"
      interval = "30s"
```

## 📊 监控和统计

### 流量统计API

```bash
# 获取总体统计
curl http://localhost:8080/stats

# 获取服务统计
curl http://localhost:8080/stats/services

# 获取路径统计
curl http://localhost:8080/stats/paths

# 获取指定时间范围统计
curl "http://localhost:8080/stats/range?start=-1h&end=now"
```

### 健康检查

```bash
# 网关健康检查
curl http://localhost:8080/health

# 流量统计健康检查
curl http://localhost:8080/ping
```

## 🔧 命令行参数

```bash
./rainbowbridge [OPTIONS]

OPTIONS:
  -config string
        Configuration file path (default "configs/rainbowbridge.toml")
  -log-level string
        Log level (DEBUG, INFO, WARN, ERROR, FATAL) (default "INFO")
  -debug
        Enable debug mode
  -version
        Show version information
```

## 🧪 示例用法

### 1. HTTP到gRPC代理

```toml
[http.routers.grpc-gateway]
  entryPoints = ["https"]
  rule = "Host(`grpc.example.com`)"
  service = "grpc-service"
  middlewares = ["grpc-converter"]
```

### 2. WebSocket支持

```toml
[http.routers.websocket]
  entryPoints = ["https"]
  rule = "Host(`ws.example.com`) && PathPrefix(`/ws`)"
  service = "websocket-service"
```

### 3. 静态文件服务

```toml
[http.routers.static]
  entryPoints = ["https"]
  rule = "PathPrefix(`/static`)"
  service = "static-service"
  middlewares = ["compress"]
```

## 🤝 贡献指南

我们欢迎所有形式的贡献！请查看 [CONTRIBUTING.md](CONTRIBUTING.md) 了解详细信息。

### 开发环境设置

```bash
# 克隆项目
git clone https://github.com/landers1037/RainbowBridge.git
cd RainbowBridge

# 安装开发依赖
go mod download

# 运行测试
go test ./...

# 代码格式化
go fmt ./...

# 静态检查
go vet ./...
```

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🙏 致谢

- [Gin](https://github.com/gin-gonic/gin) - HTTP Web框架
- [Zap](https://github.com/uber-go/zap) - 高性能日志库
- [InfluxDB](https://github.com/influxdata/influxdb) - 时序数据库
- [Traefik](https://github.com/traefik/traefik) - 配置格式参考

## 📞 联系我们

- 项目主页: [https://github.com/landers1037/RainbowBridge](https://github.com/landers1037/RainbowBridge)
- 问题反馈: [Issues](https://github.com/landers1037/RainbowBridge/issues)
- 作者: [landers1037](https://github.com/landers1037)

---

⭐ 如果这个项目对你有帮助，请给我们一个星标！