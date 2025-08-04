# 多阶段构建Dockerfile
# 第一阶段：构建阶段
FROM golang:1.21-alpine AS builder

# 设置工作目录
WORKDIR /app

# 安装必要的包
RUN apk add --no-cache git ca-certificates tzdata

# 复制go mod文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o rainbowbridge \
    cmd/rainbowbridge/main.go

# 第二阶段：运行阶段
FROM alpine:latest

# 安装ca证书和时区数据
RUN apk --no-cache add ca-certificates tzdata

# 设置时区
ENV TZ=Asia/Shanghai

# 创建非root用户
RUN addgroup -g 1001 -S rainbowbridge && \
    adduser -u 1001 -S rainbowbridge -G rainbowbridge

# 设置工作目录
WORKDIR /app

# 创建必要的目录
RUN mkdir -p /app/configs /app/logs /app/certs && \
    chown -R rainbowbridge:rainbowbridge /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/rainbowbridge /app/rainbowbridge

# 复制配置文件
COPY --chown=rainbowbridge:rainbowbridge configs/rainbowbridge.toml /app/configs/

# 设置权限
RUN chmod +x /app/rainbowbridge

# 切换到非root用户
USER rainbowbridge

# 暴露端口
EXPOSE 80 443 8080 9090

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# 启动命令
CMD ["/app/rainbowbridge", "-config", "/app/configs/rainbowbridge.toml"]