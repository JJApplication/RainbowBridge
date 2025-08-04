/*
   Project: RainbowBridge
   Github: https://github.com/landers1037
   Copyright Renj
*/

package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"rainbowbridge/internal/logger"
	"rainbowbridge/pkg/errors"

	"github.com/gin-gonic/gin"
)

// Protocol 协议类型
type Protocol string

const (
	// PROTOCOL_HTTP HTTP协议
	PROTOCOL_HTTP Protocol = "http"
	// PROTOCOL_HTTPS HTTPS协议
	PROTOCOL_HTTPS Protocol = "https"
	// PROTOCOL_TCP TCP协议
	PROTOCOL_TCP Protocol = "tcp"
	// PROTOCOL_UDP UDP协议
	PROTOCOL_UDP Protocol = "udp"
	// PROTOCOL_UDS Unix Domain Socket协议
	PROTOCOL_UDS Protocol = "uds"
)

// Config 服务器配置
type Config struct {
	// Name 服务器名称
	Name string `json:"name"`
	// Protocol 协议类型
	Protocol Protocol `json:"protocol"`
	// Address 监听地址
	Address string `json:"address"`
	// Port 监听端口
	Port int `json:"port"`
	// TLSConfig TLS配置
	TLSConfig *TLSConfig `json:"tls_config"`
	// ReadTimeout 读取超时
	ReadTimeout time.Duration `json:"read_timeout"`
	// WriteTimeout 写入超时
	WriteTimeout time.Duration `json:"write_timeout"`
	// IdleTimeout 空闲超时
	IdleTimeout time.Duration `json:"idle_timeout"`
	// MaxHeaderBytes 最大头部字节数
	MaxHeaderBytes int `json:"max_header_bytes"`
	// EnableHTTP2 是否启用HTTP2
	EnableHTTP2 bool `json:"enable_http2"`
}

// TLSConfig TLS配置
type TLSConfig struct {
	// CertFile 证书文件路径
	CertFile string `json:"cert_file"`
	// KeyFile 私钥文件路径
	KeyFile string `json:"key_file"`
	// InsecureSkipVerify 跳过证书验证
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
	// MinVersion 最小TLS版本
	MinVersion uint16 `json:"min_version"`
	// MaxVersion 最大TLS版本
	MaxVersion uint16 `json:"max_version"`
	// CipherSuites 加密套件
	CipherSuites []uint16 `json:"cipher_suites"`
}

// Server 服务器接口
type Server interface {
	// Start 启动服务器
	Start() error
	// Stop 停止服务器
	Stop(ctx context.Context) error
	// GetConfig 获取配置
	GetConfig() *Config
	// IsRunning 是否运行中
	IsRunning() bool
}

// HTTPServer HTTP服务器
type HTTPServer struct {
	// config 服务器配置指针，用于存储服务器配置信息
	config *Config
	// server HTTP服务器指针，用于处理HTTP请求
	server *http.Server
	// engine Gin引擎指针，用于路由处理
	engine *gin.Engine
	// running 运行状态，用于标识服务器是否正在运行
	running bool
	// mutex 互斥锁，用于保护运行状态的并发访问
	mutex sync.RWMutex
}

// TCPServer TCP服务器
type TCPServer struct {
	// config 服务器配置指针，用于存储服务器配置信息
	config *Config
	// listener TCP监听器指针，用于监听TCP连接
	listener net.Listener
	// running 运行状态，用于标识服务器是否正在运行
	running bool
	// mutex 互斥锁，用于保护运行状态的并发访问
	mutex sync.RWMutex
	// handler 连接处理函数，用于处理TCP连接
	handler func(net.Conn)
}

// UDPServer UDP服务器
type UDPServer struct {
	// config 服务器配置指针，用于存储服务器配置信息
	config *Config
	// conn UDP连接指针，用于处理UDP数据包
	conn *net.UDPConn
	// running 运行状态，用于标识服务器是否正在运行
	running bool
	// mutex 互斥锁，用于保护运行状态的并发访问
	mutex sync.RWMutex
	// handler 数据包处理函数，用于处理UDP数据包
	handler func(*net.UDPAddr, []byte)
}

// UDSServer Unix Domain Socket服务器
type UDSServer struct {
	// config 服务器配置指针，用于存储服务器配置信息
	config *Config
	// listener Unix监听器指针，用于监听Unix域套接字连接
	listener net.Listener
	// running 运行状态，用于标识服务器是否正在运行
	running bool
	// mutex 互斥锁，用于保护运行状态的并发访问
	mutex sync.RWMutex
	// handler 连接处理函数，用于处理Unix域套接字连接
	handler func(net.Conn)
}

// NewHTTPServer 创建HTTP服务器
func NewHTTPServer(config *Config, engine *gin.Engine) (*HTTPServer, error) {
	if config == nil {
		return nil, errors.ErrServerConfigInvalid
	}

	if engine == nil {
		engine = gin.New()
	}

	// 设置默认值
	if config.ReadTimeout == 0 {
		config.ReadTimeout = 30 * time.Second
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 30 * time.Second
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = 60 * time.Second
	}
	if config.MaxHeaderBytes == 0 {
		config.MaxHeaderBytes = 1 << 20 // 1MB
	}

	addr := fmt.Sprintf("%s:%d", config.Address, config.Port)
	server := &http.Server{
		Addr:           addr,
		Handler:        engine,
		ReadTimeout:    config.ReadTimeout,
		WriteTimeout:   config.WriteTimeout,
		IdleTimeout:    config.IdleTimeout,
		MaxHeaderBytes: config.MaxHeaderBytes,
	}

	// 配置TLS
	if config.Protocol == PROTOCOL_HTTPS && config.TLSConfig != nil {
		tlsConfig, err := buildTLSConfig(config.TLSConfig)
		if err != nil {
			return nil, fmt.Errorf("%w: build TLS config failed: %v", errors.ErrServerConfigInvalid, err)
		}
		server.TLSConfig = tlsConfig
	}

	return &HTTPServer{
		config: config,
		server: server,
		engine: engine,
	}, nil
}

// buildTLSConfig 构建TLS配置
func buildTLSConfig(config *TLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.InsecureSkipVerify,
		MinVersion:         config.MinVersion,
		MaxVersion:         config.MaxVersion,
		CipherSuites:       config.CipherSuites,
	}

	if config.MinVersion == 0 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}

	if config.CertFile != "" && config.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load certificate failed: %v", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// Start 启动HTTP服务器
func (s *HTTPServer) Start() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.running {
		return fmt.Errorf("%w: server already running", errors.ErrServerStartFailed)
	}

	logger.Infof("Starting %s server on %s:%d", s.config.Protocol, s.config.Address, s.config.Port)

	go func() {
		var err error
		if s.config.Protocol == PROTOCOL_HTTPS {
			err = s.server.ListenAndServeTLS("", "")
		} else {
			err = s.server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			logger.Errorf("HTTP server error: %v", err)
		}
	}()

	s.running = true
	return nil
}

// Stop 停止HTTP服务器
func (s *HTTPServer) Stop(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.running {
		return nil
	}

	logger.Infof("Stopping %s server", s.config.Protocol)

	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("%w: %v", errors.ErrServerStopFailed, err)
	}

	s.running = false
	return nil
}

// GetConfig 获取HTTP服务器配置
func (s *HTTPServer) GetConfig() *Config {
	return s.config
}

// IsRunning 检查HTTP服务器是否运行中
func (s *HTTPServer) IsRunning() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.running
}

// GetEngine 获取Gin引擎
func (s *HTTPServer) GetEngine() *gin.Engine {
	return s.engine
}

// GetServer 获取底层HTTP服务器
func (s *HTTPServer) GetServer() *http.Server {
	return s.server
}

// NewTCPServer 创建TCP服务器
func NewTCPServer(config *Config, handler func(net.Conn)) (*TCPServer, error) {
	if config == nil {
		return nil, errors.ErrServerConfigInvalid
	}

	if handler == nil {
		handler = func(conn net.Conn) {
			defer conn.Close()
			logger.Infof("TCP connection from %s", conn.RemoteAddr())
		}
	}

	return &TCPServer{
		config:  config,
		handler: handler,
	}, nil
}

// Start 启动TCP服务器
func (s *TCPServer) Start() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.running {
		return fmt.Errorf("%w: server already running", errors.ErrServerStartFailed)
	}

	addr := fmt.Sprintf("%s:%d", s.config.Address, s.config.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("%w: %v", errors.ErrServerStartFailed, err)
	}

	s.listener = listener
	s.running = true

	logger.Infof("Starting TCP server on %s", addr)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if s.running {
					logger.Errorf("TCP accept error: %v", err)
				}
				return
			}

			go s.handler(conn)
		}
	}()

	return nil
}

// Stop 停止TCP服务器
func (s *TCPServer) Stop(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.running {
		return nil
	}

	logger.Infof("Stopping TCP server")

	s.running = false
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			return fmt.Errorf("%w: %v", errors.ErrServerStopFailed, err)
		}
	}

	return nil
}

// GetConfig 获取TCP服务器配置
func (s *TCPServer) GetConfig() *Config {
	return s.config
}

// IsRunning 检查TCP服务器是否运行中
func (s *TCPServer) IsRunning() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.running
}

// NewUDPServer 创建UDP服务器
func NewUDPServer(config *Config, handler func(*net.UDPAddr, []byte)) (*UDPServer, error) {
	if config == nil {
		return nil, errors.ErrServerConfigInvalid
	}

	if handler == nil {
		handler = func(addr *net.UDPAddr, data []byte) {
			logger.Infof("UDP packet from %s: %d bytes", addr, len(data))
		}
	}

	return &UDPServer{
		config:  config,
		handler: handler,
	}, nil
}

// Start 启动UDP服务器
func (s *UDPServer) Start() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.running {
		return fmt.Errorf("%w: server already running", errors.ErrServerStartFailed)
	}

	addr := fmt.Sprintf("%s:%d", s.config.Address, s.config.Port)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("%w: %v", errors.ErrServerStartFailed, err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("%w: %v", errors.ErrServerStartFailed, err)
	}

	s.conn = conn
	s.running = true

	logger.Infof("Starting UDP server on %s", addr)

	go func() {
		buffer := make([]byte, 4096)
		for {
			n, clientAddr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				if s.running {
					logger.Errorf("UDP read error: %v", err)
				}
				return
			}

			data := make([]byte, n)
			copy(data, buffer[:n])
			go s.handler(clientAddr, data)
		}
	}()

	return nil
}

// Stop 停止UDP服务器
func (s *UDPServer) Stop(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.running {
		return nil
	}

	logger.Infof("Stopping UDP server")

	s.running = false
	if s.conn != nil {
		if err := s.conn.Close(); err != nil {
			return fmt.Errorf("%w: %v", errors.ErrServerStopFailed, err)
		}
	}

	return nil
}

// GetConfig 获取UDP服务器配置
func (s *UDPServer) GetConfig() *Config {
	return s.config
}

// IsRunning 检查UDP服务器是否运行中
func (s *UDPServer) IsRunning() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.running
}

// NewUDSServer 创建Unix Domain Socket服务器
func NewUDSServer(config *Config, handler func(net.Conn)) (*UDSServer, error) {
	if config == nil {
		return nil, errors.ErrServerConfigInvalid
	}

	if handler == nil {
		handler = func(conn net.Conn) {
			defer conn.Close()
			logger.Infof("UDS connection from %s", conn.RemoteAddr())
		}
	}

	return &UDSServer{
		config:  config,
		handler: handler,
	}, nil
}

// Start 启动UDS服务器
func (s *UDSServer) Start() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.running {
		return fmt.Errorf("%w: server already running", errors.ErrServerStartFailed)
	}

	listener, err := net.Listen("unix", s.config.Address)
	if err != nil {
		return fmt.Errorf("%w: %v", errors.ErrServerStartFailed, err)
	}

	s.listener = listener
	s.running = true

	logger.Infof("Starting UDS server on %s", s.config.Address)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if s.running {
					logger.Errorf("UDS accept error: %v", err)
				}
				return
			}

			go s.handler(conn)
		}
	}()

	return nil
}

// Stop 停止UDS服务器
func (s *UDSServer) Stop(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.running {
		return nil
	}

	logger.Infof("Stopping UDS server")

	s.running = false
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			return fmt.Errorf("%w: %v", errors.ErrServerStopFailed, err)
		}
	}

	return nil
}

// GetConfig 获取UDS服务器配置
func (s *UDSServer) GetConfig() *Config {
	return s.config
}

// IsRunning 检查UDS服务器是否运行中
func (s *UDSServer) IsRunning() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.running
}

// NewServer 根据协议创建服务器
func NewServer(config *Config, options ...interface{}) (Server, error) {
	switch config.Protocol {
	case PROTOCOL_HTTP, PROTOCOL_HTTPS:
		var engine *gin.Engine
		if len(options) > 0 {
			if e, ok := options[0].(*gin.Engine); ok {
				engine = e
			}
		}
		return NewHTTPServer(config, engine)
	case PROTOCOL_TCP:
		var handler func(net.Conn)
		if len(options) > 0 {
			if h, ok := options[0].(func(net.Conn)); ok {
				handler = h
			}
		}
		return NewTCPServer(config, handler)
	case PROTOCOL_UDP:
		var handler func(*net.UDPAddr, []byte)
		if len(options) > 0 {
			if h, ok := options[0].(func(*net.UDPAddr, []byte)); ok {
				handler = h
			}
		}
		return NewUDPServer(config, handler)
	case PROTOCOL_UDS:
		var handler func(net.Conn)
		if len(options) > 0 {
			if h, ok := options[0].(func(net.Conn)); ok {
				handler = h
			}
		}
		return NewUDSServer(config, handler)
	default:
		return nil, fmt.Errorf("%w: unsupported protocol: %s", errors.ErrServerConfigInvalid, config.Protocol)
	}
}
