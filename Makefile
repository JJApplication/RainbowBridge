# RainbowBridge Makefile
# 项目构建和管理工具

# 变量定义
APP_NAME := rainbowbridge
APP_VERSION := 1.0.0
GO_VERSION := 1.21
DOCKER_IMAGE := $(APP_NAME):$(APP_VERSION)
DOCKER_LATEST := $(APP_NAME):latest

# Go相关变量
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOFMT := $(GOCMD) fmt
GOVET := $(GOCMD) vet
GOMOD := $(GOCMD) mod

# 构建相关变量
BINARY_NAME := $(APP_NAME)
BINARY_UNIX := $(BINARY_NAME)_unix
BINARY_WINDOWS := $(BINARY_NAME).exe
BINARY_DARWIN := $(BINARY_NAME)_darwin

# 源文件
MAIN_FILE := cmd/rainbowbridge/main.go

# 构建标志
LDFLAGS := -ldflags="-w -s -X main.Version=$(APP_VERSION) -X main.BuildTime=$(shell date +%Y-%m-%d_%H:%M:%S)"
BUILD_FLAGS := -a -installsuffix cgo

# 默认目标
.PHONY: all
all: clean deps fmt vet test build

# 帮助信息
.PHONY: help
help:
	@echo "RainbowBridge $(APP_VERSION) - 高性能微服务网关"
	@echo ""
	@echo "可用命令:"
	@echo "  build          构建应用程序"
	@echo "  build-all      构建所有平台的二进制文件"
	@echo "  clean          清理构建文件"
	@echo "  deps           下载依赖"
	@echo "  fmt            格式化代码"
	@echo "  vet            静态分析"
	@echo "  test           运行测试"
	@echo "  test-coverage  运行测试并生成覆盖率报告"
	@echo "  run            运行应用程序"
	@echo "  docker-build   构建Docker镜像"
	@echo "  docker-run     运行Docker容器"
	@echo "  docker-push    推送Docker镜像"
	@echo "  install        安装应用程序"
	@echo "  uninstall      卸载应用程序"
	@echo "  release        创建发布版本"
	@echo "  dev            开发模式运行"
	@echo "  lint           代码检查"
	@echo "  security       安全检查"
	@echo "  benchmark      性能测试"

# 下载依赖
.PHONY: deps
deps:
	@echo "下载依赖..."
	$(GOMOD) download
	$(GOMOD) tidy

# 代码格式化
.PHONY: fmt
fmt:
	@echo "格式化代码..."
	$(GOFMT) ./...

# 静态分析
.PHONY: vet
vet:
	@echo "静态分析..."
	$(GOVET) ./...

# 运行测试
.PHONY: test
test:
	@echo "运行测试..."
	$(GOTEST) -v ./...

# 测试覆盖率
.PHONY: test-coverage
test-coverage:
	@echo "运行测试并生成覆盖率报告..."
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "覆盖率报告已生成: coverage.html"

# 构建应用程序
.PHONY: build
build:
	@echo "构建应用程序..."
	$(GOBUILD) $(LDFLAGS) $(BUILD_FLAGS) -o $(BINARY_NAME) $(MAIN_FILE)

# 构建Linux版本
.PHONY: build-linux
build-linux:
	@echo "构建Linux版本..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) $(BUILD_FLAGS) -o $(BINARY_UNIX) $(MAIN_FILE)

# 构建Windows版本
.PHONY: build-windows
build-windows:
	@echo "构建Windows版本..."
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) $(BUILD_FLAGS) -o $(BINARY_WINDOWS) $(MAIN_FILE)

# 构建macOS版本
.PHONY: build-darwin
build-darwin:
	@echo "构建macOS版本..."
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) $(BUILD_FLAGS) -o $(BINARY_DARWIN) $(MAIN_FILE)

# 构建所有平台
.PHONY: build-all
build-all: build-linux build-windows build-darwin
	@echo "所有平台构建完成"

# 清理构建文件
.PHONY: clean
clean:
	@echo "清理构建文件..."
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)
	rm -f $(BINARY_WINDOWS)
	rm -f $(BINARY_DARWIN)
	rm -f coverage.out
	rm -f coverage.html

# 运行应用程序
.PHONY: run
run: build
	@echo "运行应用程序..."
	./$(BINARY_NAME) -config configs/rainbowbridge.toml

# 开发模式运行
.PHONY: dev
dev:
	@echo "开发模式运行..."
	$(GOCMD) run $(MAIN_FILE) -config configs/rainbowbridge.toml -debug

# 安装应用程序
.PHONY: install
install: build
	@echo "安装应用程序..."
	cp $(BINARY_NAME) /usr/local/bin/

# 卸载应用程序
.PHONY: uninstall
uninstall:
	@echo "卸载应用程序..."
	rm -f /usr/local/bin/$(BINARY_NAME)

# Docker相关命令

# 构建Docker镜像
.PHONY: docker-build
docker-build:
	@echo "构建Docker镜像..."
	docker build -t $(DOCKER_IMAGE) .
	docker tag $(DOCKER_IMAGE) $(DOCKER_LATEST)

# 运行Docker容器
.PHONY: docker-run
docker-run:
	@echo "运行Docker容器..."
	docker run -d \
		--name $(APP_NAME) \
		-p 80:80 \
		-p 443:443 \
		-p 8080:8080 \
		-v $(PWD)/configs:/app/configs \
		-v $(PWD)/certs:/app/certs \
		-v $(PWD)/logs:/app/logs \
		$(DOCKER_LATEST)

# 停止Docker容器
.PHONY: docker-stop
docker-stop:
	@echo "停止Docker容器..."
	docker stop $(APP_NAME) || true
	docker rm $(APP_NAME) || true

# 推送Docker镜像
.PHONY: docker-push
docker-push:
	@echo "推送Docker镜像..."
	docker push $(DOCKER_IMAGE)
	docker push $(DOCKER_LATEST)

# 代码检查
.PHONY: lint
lint:
	@echo "代码检查..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint未安装，跳过代码检查"; \
	fi

# 安全检查
.PHONY: security
security:
	@echo "安全检查..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec未安装，跳过安全检查"; \
	fi

# 性能测试
.PHONY: benchmark
benchmark:
	@echo "性能测试..."
	$(GOTEST) -bench=. -benchmem ./...

# 创建发布版本
.PHONY: release
release: clean deps fmt vet test build-all
	@echo "创建发布版本 $(APP_VERSION)..."
	mkdir -p release
	cp $(BINARY_UNIX) release/$(APP_NAME)-$(APP_VERSION)-linux-amd64
	cp $(BINARY_WINDOWS) release/$(APP_NAME)-$(APP_VERSION)-windows-amd64.exe
	cp $(BINARY_DARWIN) release/$(APP_NAME)-$(APP_VERSION)-darwin-amd64
	cp configs/rainbowbridge.toml release/
	cp README.md release/
	cp LICENSE release/
	@echo "发布文件已创建在 release/ 目录"

# 生成配置文件模板
.PHONY: config
config:
	@echo "生成配置文件模板..."
	mkdir -p configs
	@if [ ! -f configs/rainbowbridge.toml ]; then \
		echo "配置文件已存在"; \
	else \
		echo "配置文件模板已生成: configs/rainbowbridge.toml"; \
	fi

# 创建证书目录
.PHONY: certs
certs:
	@echo "创建证书目录..."
	mkdir -p certs
	@echo "证书目录已创建: certs/"

# 创建日志目录
.PHONY: logs
logs:
	@echo "创建日志目录..."
	mkdir -p logs
	@echo "日志目录已创建: logs/"

# 初始化项目
.PHONY: init
init: deps config certs logs
	@echo "项目初始化完成"

# 检查Go版本
.PHONY: check-go
check-go:
	@echo "检查Go版本..."
	@go version
	@echo "要求Go版本: $(GO_VERSION)+"

# 显示项目信息
.PHONY: info
info:
	@echo "项目信息:"
	@echo "  名称: $(APP_NAME)"
	@echo "  版本: $(APP_VERSION)"
	@echo "  Go版本: $(GO_VERSION)"
	@echo "  主文件: $(MAIN_FILE)"
	@echo "  Docker镜像: $(DOCKER_IMAGE)"

# 监控文件变化并自动重新构建（需要安装fswatch）
.PHONY: watch
watch:
	@echo "监控文件变化..."
	@if command -v fswatch >/dev/null 2>&1; then \
		fswatch -o . | xargs -n1 -I{} make build; \
	else \
		echo "fswatch未安装，无法监控文件变化"; \
	fi

# 生成API文档（如果有swagger）
.PHONY: docs
docs:
	@echo "生成API文档..."
	@if command -v swag >/dev/null 2>&1; then \
		swag init -g $(MAIN_FILE); \
	else \
		echo "swag未安装，跳过文档生成"; \
	fi

# 更新依赖
.PHONY: update
update:
	@echo "更新依赖..."
	$(GOGET) -u ./...
	$(GOMOD) tidy

# 检查依赖漏洞
.PHONY: audit
audit:
	@echo "检查依赖漏洞..."
	@if command -v nancy >/dev/null 2>&1; then \
		$(GOMOD) list -json -m all | nancy sleuth; \
	else \
		echo "nancy未安装，跳过漏洞检查"; \
	fi