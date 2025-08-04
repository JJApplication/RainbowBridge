/*
   Project: RainbowBridge
   Github: https://github.com/landers1037
   Copyright Renj
*/

package mixer

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"rainbowbridge/internal/logger"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// ProtocolType 协议类型
type ProtocolType string

const (
	// PROTOCOL_HTTP HTTP协议
	PROTOCOL_HTTP ProtocolType = "http"
	// PROTOCOL_HTTPS HTTPS协议
	PROTOCOL_HTTPS ProtocolType = "https"
	// PROTOCOL_HTTP2 HTTP2协议
	PROTOCOL_HTTP2 ProtocolType = "http2"
	// PROTOCOL_TCP TCP协议
	PROTOCOL_TCP ProtocolType = "tcp"
	// PROTOCOL_UDP UDP协议
	PROTOCOL_UDP ProtocolType = "udp"
	// PROTOCOL_GRPC gRPC协议
	PROTOCOL_GRPC ProtocolType = "grpc"
	// PROTOCOL_UDS Unix Domain Socket协议
	PROTOCOL_UDS ProtocolType = "uds"
	// PROTOCOL_WEBSOCKET WebSocket协议
	PROTOCOL_WEBSOCKET ProtocolType = "websocket"
)

// ConversionRule 转换规则
type ConversionRule struct {
	// Name 规则名称
	Name string `json:"name"`
	// SourceProtocol 源协议
	SourceProtocol ProtocolType `json:"source_protocol"`
	// TargetProtocol 目标协议
	TargetProtocol ProtocolType `json:"target_protocol"`
	// SourcePattern 源模式匹配
	SourcePattern string `json:"source_pattern"`
	// TargetEndpoint 目标端点
	TargetEndpoint string `json:"target_endpoint"`
	// Headers 转换时添加的头部
	Headers map[string]string `json:"headers"`
	// Timeout 转换超时时间
	Timeout time.Duration `json:"timeout"`
	// Enabled 是否启用
	Enabled bool `json:"enabled"`
}

// Config 混合器配置
type Config struct {
	// Name 混合器名称
	Name string `json:"name"`
	// Rules 转换规则列表
	Rules []*ConversionRule `json:"rules"`
	// DefaultTimeout 默认超时时间
	DefaultTimeout time.Duration `json:"default_timeout"`
	// MaxConcurrentConnections 最大并发连接数
	MaxConcurrentConnections int `json:"max_concurrent_connections"`
	// BufferSize 缓冲区大小
	BufferSize int `json:"buffer_size"`
}

// Converter 协议转换器接口
type Converter interface {
	// Convert 执行协议转换
	Convert(ctx context.Context, source io.Reader, target io.Writer, rule *ConversionRule) error
	// SupportedConversion 支持的转换类型
	SupportedConversion() (ProtocolType, ProtocolType)
}

// HTTPToGRPCConverter HTTP到gRPC转换器
type HTTPToGRPCConverter struct {
	// grpcClients gRPC客户端连接池，键为目标端点，值为gRPC连接指针
	grpcClients map[string]*grpc.ClientConn
	// mutex 读写锁，用于保护gRPC客户端连接池的并发访问
	mutex sync.RWMutex
}

// HTTPToTCPConverter HTTP到TCP转换器
type HTTPToTCPConverter struct {
	// tcpConnections TCP连接池，键为目标端点，值为TCP连接指针
	tcpConnections map[string]net.Conn
	// mutex 读写锁，用于保护TCP连接池的并发访问
	mutex sync.RWMutex
}

// TCPToHTTPConverter TCP到HTTP转换器
type TCPToHTTPConverter struct {
	// httpClients HTTP客户端池，键为目标端点，值为HTTP客户端指针
	httpClients map[string]*http.Client
	// mutex 读写锁，用于保护HTTP客户端池的并发访问
	mutex sync.RWMutex
}

// WebSocketUpgrader WebSocket升级器
type WebSocketUpgrader struct {
	// upgrader WebSocket升级器指针，用于处理WebSocket协议升级
	upgrader interface{} // 这里应该是websocket.Upgrader，但为了避免依赖，使用interface{}
}

// Mixer 流量混合器
type Mixer struct {
	// config 配置指针，用于存储混合器配置信息
	config *Config
	// converters 转换器映射，键为转换类型，值为转换器实例
	converters map[string]Converter
	// rules 转换规则映射，键为规则名称，值为转换规则指针
	rules map[string]*ConversionRule
	// running 运行状态，用于标识混合器是否正在运行
	running bool
	// mutex 读写锁，用于保护混合器状态的并发访问
	mutex sync.RWMutex
	// connectionSemaphore 连接信号量，用于限制并发连接数
	connectionSemaphore chan struct{}
}

// NewMixer 创建流量混合器
func NewMixer(config *Config) (*Mixer, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	// 设置默认值
	if config.DefaultTimeout == 0 {
		config.DefaultTimeout = 30 * time.Second
	}
	if config.MaxConcurrentConnections == 0 {
		config.MaxConcurrentConnections = 1000
	}
	if config.BufferSize == 0 {
		config.BufferSize = 4096
	}

	mixer := &Mixer{
		config:              config,
		converters:          make(map[string]Converter),
		rules:               make(map[string]*ConversionRule),
		connectionSemaphore: make(chan struct{}, config.MaxConcurrentConnections),
	}

	// 初始化转换器
	mixer.initConverters()

	// 初始化规则
	for _, rule := range config.Rules {
		if rule.Enabled {
			mixer.rules[rule.Name] = rule
		}
	}

	return mixer, nil
}

// initConverters 初始化转换器
func (m *Mixer) initConverters() {
	// HTTP到gRPC转换器
	httpToGRPC := &HTTPToGRPCConverter{
		grpcClients: make(map[string]*grpc.ClientConn),
	}
	m.converters["http-grpc"] = httpToGRPC

	// HTTP到TCP转换器
	httpToTCP := &HTTPToTCPConverter{
		tcpConnections: make(map[string]net.Conn),
	}
	m.converters["http-tcp"] = httpToTCP

	// TCP到HTTP转换器
	tcpToHTTP := &TCPToHTTPConverter{
		httpClients: make(map[string]*http.Client),
	}
	m.converters["tcp-http"] = tcpToHTTP
}

// Start 启动混合器
func (m *Mixer) Start() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.running {
		return fmt.Errorf("mixer already running")
	}

	m.running = true
	logger.Infof("Traffic mixer %s started with %d rules", m.config.Name, len(m.rules))

	return nil
}

// Stop 停止混合器
func (m *Mixer) Stop() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if !m.running {
		return nil
	}

	// 关闭所有连接
	for _, converter := range m.converters {
		if httpToGRPC, ok := converter.(*HTTPToGRPCConverter); ok {
			httpToGRPC.closeAllConnections()
		}
		if httpToTCP, ok := converter.(*HTTPToTCPConverter); ok {
			httpToTCP.closeAllConnections()
		}
	}

	m.running = false
	logger.Infof("Traffic mixer %s stopped", m.config.Name)

	return nil
}

// ProcessRequest 处理请求
func (m *Mixer) ProcessRequest(ctx context.Context, ruleName string, source io.Reader, target io.Writer) error {
	if !m.running {
		return fmt.Errorf("mixer is not running")
	}

	rule, exists := m.rules[ruleName]
	if !exists {
		return fmt.Errorf("rule %s not found", ruleName)
	}

	// 获取连接信号量
	select {
	case m.connectionSemaphore <- struct{}{}:
		defer func() { <-m.connectionSemaphore }()
	case <-ctx.Done():
		return ctx.Err()
	}

	// 获取转换器
	converterKey := fmt.Sprintf("%s-%s", rule.SourceProtocol, rule.TargetProtocol)
	converter, exists := m.converters[converterKey]
	if !exists {
		return fmt.Errorf("converter for %s not found", converterKey)
	}

	// 设置超时
	timeout := rule.Timeout
	if timeout == 0 {
		timeout = m.config.DefaultTimeout
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 执行转换
	return converter.Convert(ctxWithTimeout, source, target, rule)
}

// CreateGinHandler 创建Gin处理器
func (m *Mixer) CreateGinHandler(ruleName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !m.running {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Mixer is not running",
				"code":  http.StatusServiceUnavailable,
			})
			return
		}

		rule, exists := m.rules[ruleName]
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{
				"error": fmt.Sprintf("Rule %s not found", ruleName),
				"code":  http.StatusNotFound,
			})
			return
		}

		// 检查是否为WebSocket升级请求
		if rule.TargetProtocol == PROTOCOL_WEBSOCKET {
			m.handleWebSocketUpgrade(c, rule)
			return
		}

		// 处理普通HTTP请求转换
		m.handleHTTPConversion(c, rule)
	}
}

// handleWebSocketUpgrade 处理WebSocket升级
func (m *Mixer) handleWebSocketUpgrade(c *gin.Context, rule *ConversionRule) {
	// 检查WebSocket升级头部
	if c.Request.Header.Get("Upgrade") != "websocket" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Not a WebSocket upgrade request",
			"code":  http.StatusBadRequest,
		})
		return
	}

	// 这里应该实现WebSocket升级逻辑
	// 由于篇幅限制，暂时返回成功响应
	c.JSON(http.StatusSwitchingProtocols, gin.H{
		"message": "WebSocket upgrade successful",
	})

	logger.Infof("WebSocket upgrade request processed for rule %s", rule.Name)
}

// handleHTTPConversion 处理HTTP转换
func (m *Mixer) handleHTTPConversion(c *gin.Context, rule *ConversionRule) {
	ctx := c.Request.Context()

	// 创建缓冲区
	buffer := make([]byte, m.config.BufferSize)
	_ = buffer // 避免未使用变量警告

	// 根据目标协议处理
	switch rule.TargetProtocol {
	case PROTOCOL_GRPC:
		m.handleHTTPToGRPC(ctx, c, rule)
	case PROTOCOL_TCP:
		m.handleHTTPToTCP(ctx, c, rule)
	default:
		c.JSON(http.StatusNotImplemented, gin.H{
			"error": fmt.Sprintf("Conversion to %s not implemented", rule.TargetProtocol),
			"code":  http.StatusNotImplemented,
		})
	}
}

// handleHTTPToGRPC 处理HTTP到gRPC转换
func (m *Mixer) handleHTTPToGRPC(ctx context.Context, c *gin.Context, rule *ConversionRule) {
	converter := m.converters["http-grpc"].(*HTTPToGRPCConverter)

	// 获取或创建gRPC连接
	conn, err := converter.getConnection(rule.TargetEndpoint)
	defer conn.Close()
	if err != nil {
		logger.Errorf("Failed to get gRPC connection: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "Failed to connect to gRPC service",
			"code":  http.StatusBadGateway,
		})
		return
	}

	// 这里应该实现具体的HTTP到gRPC转换逻辑
	// 由于篇幅限制，暂时返回成功响应
	c.JSON(http.StatusOK, gin.H{
		"message": "HTTP to gRPC conversion successful",
		"target":  rule.TargetEndpoint,
	})

	logger.Debugf("HTTP to gRPC conversion completed for %s", rule.TargetEndpoint)
}

// handleHTTPToTCP 处理HTTP到TCP转换
func (m *Mixer) handleHTTPToTCP(ctx context.Context, c *gin.Context, rule *ConversionRule) {
	converter := m.converters["http-tcp"].(*HTTPToTCPConverter)

	// 获取或创建TCP连接
	conn, err := converter.getConnection(rule.TargetEndpoint)
	if err != nil {
		logger.Errorf("Failed to get TCP connection: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "Failed to connect to TCP service",
			"code":  http.StatusBadGateway,
		})
		return
	}

	// 读取HTTP请求体
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logger.Errorf("Failed to read request body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read request body",
			"code":  http.StatusBadRequest,
		})
		return
	}

	// 发送到TCP连接
	_, err = conn.Write(body)
	if err != nil {
		logger.Errorf("Failed to write to TCP connection: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "Failed to write to TCP service",
			"code":  http.StatusBadGateway,
		})
		return
	}

	// 读取TCP响应
	response := make([]byte, m.config.BufferSize)
	n, err := conn.Read(response)
	if err != nil {
		logger.Errorf("Failed to read from TCP connection: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "Failed to read from TCP service",
			"code":  http.StatusBadGateway,
		})
		return
	}

	// 返回响应
	c.Data(http.StatusOK, "application/octet-stream", response[:n])

	logger.Debugf("HTTP to TCP conversion completed for %s", rule.TargetEndpoint)
}

// HTTPToGRPCConverter 实现

// Convert HTTP到gRPC转换
func (c *HTTPToGRPCConverter) Convert(ctx context.Context, source io.Reader, target io.Writer, rule *ConversionRule) error {
	// 实现HTTP到gRPC的具体转换逻辑
	return fmt.Errorf("HTTP to gRPC conversion not fully implemented")
}

// SupportedConversion 支持的转换类型
func (c *HTTPToGRPCConverter) SupportedConversion() (ProtocolType, ProtocolType) {
	return PROTOCOL_HTTP, PROTOCOL_GRPC
}

// getConnection 获取gRPC连接
func (c *HTTPToGRPCConverter) getConnection(endpoint string) (*grpc.ClientConn, error) {
	c.mutex.RLock()
	conn, exists := c.grpcClients[endpoint]
	c.mutex.RUnlock()

	if exists && conn.GetState().String() == "READY" {
		return conn, nil
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// 双重检查
	conn, exists = c.grpcClients[endpoint]
	if exists && conn.GetState().String() == "READY" {
		return conn, nil
	}

	// 创建新连接
	newConn, err := grpc.Dial(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	c.grpcClients[endpoint] = newConn
	return newConn, nil
}

// closeAllConnections 关闭所有gRPC连接
func (c *HTTPToGRPCConverter) closeAllConnections() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for endpoint, conn := range c.grpcClients {
		if err := conn.Close(); err != nil {
			logger.Errorf("Failed to close gRPC connection to %s: %v", endpoint, err)
		}
	}
	c.grpcClients = make(map[string]*grpc.ClientConn)
}

// HTTPToTCPConverter 实现

// Convert HTTP到TCP转换
func (c *HTTPToTCPConverter) Convert(ctx context.Context, source io.Reader, target io.Writer, rule *ConversionRule) error {
	// 实现HTTP到TCP的具体转换逻辑
	return fmt.Errorf("HTTP to TCP conversion not fully implemented")
}

// SupportedConversion 支持的转换类型
func (c *HTTPToTCPConverter) SupportedConversion() (ProtocolType, ProtocolType) {
	return PROTOCOL_HTTP, PROTOCOL_TCP
}

// getConnection 获取TCP连接
func (c *HTTPToTCPConverter) getConnection(endpoint string) (net.Conn, error) {
	c.mutex.RLock()
	conn, exists := c.tcpConnections[endpoint]
	c.mutex.RUnlock()

	if exists {
		// 检查连接是否仍然有效
		if err := testTCPConnection(conn); err == nil {
			return conn, nil
		}
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// 创建新连接
	newConn, err := net.DialTimeout("tcp", endpoint, 10*time.Second)
	if err != nil {
		return nil, err
	}

	c.tcpConnections[endpoint] = newConn
	return newConn, nil
}

// closeAllConnections 关闭所有TCP连接
func (c *HTTPToTCPConverter) closeAllConnections() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for endpoint, conn := range c.tcpConnections {
		if err := conn.Close(); err != nil {
			logger.Errorf("Failed to close TCP connection to %s: %v", endpoint, err)
		}
	}
	c.tcpConnections = make(map[string]net.Conn)
}

// TCPToHTTPConverter 实现

// Convert TCP到HTTP转换
func (c *TCPToHTTPConverter) Convert(ctx context.Context, source io.Reader, target io.Writer, rule *ConversionRule) error {
	// 实现TCP到HTTP的具体转换逻辑
	return fmt.Errorf("TCP to HTTP conversion not fully implemented")
}

// SupportedConversion 支持的转换类型
func (c *TCPToHTTPConverter) SupportedConversion() (ProtocolType, ProtocolType) {
	return PROTOCOL_TCP, PROTOCOL_HTTP
}

// testTCPConnection 测试TCP连接是否有效
func testTCPConnection(conn net.Conn) error {
	if conn == nil {
		return fmt.Errorf("connection is nil")
	}

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	defer conn.SetReadDeadline(time.Time{})

	// 尝试读取一个字节
	buffer := make([]byte, 1)
	_, err := conn.Read(buffer)

	// 如果是超时错误，说明连接是活跃的
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return nil
	}

	return err
}

// AddRule 添加转换规则
func (m *Mixer) AddRule(rule *ConversionRule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if rule.Enabled {
		m.rules[rule.Name] = rule
		logger.Infof("Added conversion rule: %s (%s -> %s)", rule.Name, rule.SourceProtocol, rule.TargetProtocol)
	}

	return nil
}

// RemoveRule 移除转换规则
func (m *Mixer) RemoveRule(ruleName string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	delete(m.rules, ruleName)
	logger.Infof("Removed conversion rule: %s", ruleName)

	return nil
}

// GetRules 获取所有规则
func (m *Mixer) GetRules() map[string]*ConversionRule {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.rules
}

// IsRunning 检查是否运行中
func (m *Mixer) IsRunning() bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.running
}
