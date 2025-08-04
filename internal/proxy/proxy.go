/*
   Project: RainbowBridge
   Github: https://github.com/landers1037
   Copyright Renj
*/

package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"rainbowbridge/internal/logger"
	"rainbowbridge/pkg/errors"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
)

// ProxyType 代理类型
type ProxyType string

const (
	// PROXY_TYPE_HTTP HTTP代理
	PROXY_TYPE_HTTP ProxyType = "http"
	// PROXY_TYPE_HTTPS HTTPS代理
	PROXY_TYPE_HTTPS ProxyType = "https"
	// PROXY_TYPE_TCP TCP代理
	PROXY_TYPE_TCP ProxyType = "tcp"
	// PROXY_TYPE_UDP UDP代理
	PROXY_TYPE_UDP ProxyType = "udp"
	// PROXY_TYPE_GRPC gRPC代理
	PROXY_TYPE_GRPC ProxyType = "grpc"
	// PROXY_TYPE_UDS Unix Domain Socket代理
	PROXY_TYPE_UDS ProxyType = "uds"
)

// LoadBalanceStrategy 负载均衡策略
type LoadBalanceStrategy string

const (
	// STRATEGY_ROUND_ROBIN 轮询
	STRATEGY_ROUND_ROBIN LoadBalanceStrategy = "round_robin"
	// STRATEGY_RANDOM 随机
	STRATEGY_RANDOM LoadBalanceStrategy = "random"
	// STRATEGY_LEAST_CONN 最少连接
	STRATEGY_LEAST_CONN LoadBalanceStrategy = "least_conn"
	// STRATEGY_WEIGHTED 权重
	STRATEGY_WEIGHTED LoadBalanceStrategy = "weighted"
)

// Config 代理配置
type Config struct {
	// Name 代理名称
	Name string `json:"name"`
	// Type 代理类型
	Type ProxyType `json:"type"`
	// Targets 目标服务器列表
	Targets []*Target `json:"targets"`
	// LoadBalanceStrategy 负载均衡策略
	LoadBalanceStrategy LoadBalanceStrategy `json:"load_balance_strategy"`
	// HealthCheck 健康检查配置
	HealthCheck *HealthCheckConfig `json:"health_check"`
	// Timeout 超时配置
	Timeout *TimeoutConfig `json:"timeout"`
	// TLSConfig TLS配置
	TLSConfig *TLSConfig `json:"tls_config"`
	// RetryConfig 重试配置
	RetryConfig *RetryConfig `json:"retry_config"`
}

// Target 目标服务器
type Target struct {
	// URL 目标URL
	URL string `json:"url"`
	// Weight 权重
	Weight int `json:"weight"`
	// Healthy 是否健康
	Healthy bool `json:"healthy"`
	// Connections 当前连接数
	Connections int64 `json:"connections"`
	// LastCheck 最后检查时间
	LastCheck time.Time `json:"last_check"`
}

// HealthCheckConfig 健康检查配置
type HealthCheckConfig struct {
	// Enabled 是否启用
	Enabled bool `json:"enabled"`
	// Interval 检查间隔
	Interval time.Duration `json:"interval"`
	// Timeout 检查超时
	Timeout time.Duration `json:"timeout"`
	// Path 检查路径
	Path string `json:"path"`
	// ExpectedStatus 期望状态码
	ExpectedStatus int `json:"expected_status"`
}

// TimeoutConfig 超时配置
type TimeoutConfig struct {
	// Connect 连接超时
	Connect time.Duration `json:"connect"`
	// Read 读取超时
	Read time.Duration `json:"read"`
	// Write 写入超时
	Write time.Duration `json:"write"`
	// Idle 空闲超时
	Idle time.Duration `json:"idle"`
}

// TLSConfig TLS配置
type TLSConfig struct {
	// InsecureSkipVerify 跳过证书验证
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
	// CertFile 证书文件
	CertFile string `json:"cert_file"`
	// KeyFile 私钥文件
	KeyFile string `json:"key_file"`
	// CAFile CA证书文件
	CAFile string `json:"ca_file"`
}

// RetryConfig 重试配置
type RetryConfig struct {
	// MaxRetries 最大重试次数
	MaxRetries int `json:"max_retries"`
	// RetryDelay 重试延迟
	RetryDelay time.Duration `json:"retry_delay"`
	// RetryCondition 重试条件
	RetryCondition func(error) bool `json:"-"`
}

// Proxy 代理接口
type Proxy interface {
	// Start 启动代理
	Start() error
	// Stop 停止代理
	Stop() error
	// GetConfig 获取配置
	GetConfig() *Config
	// GetTargets 获取目标列表
	GetTargets() []*Target
	// AddTarget 添加目标
	AddTarget(target *Target) error
	// RemoveTarget 移除目标
	RemoveTarget(url string) error
}

// HTTPProxy HTTP代理
type HTTPProxy struct {
	// config 代理配置指针，用于存储代理配置信息
	config *Config
	// targets 目标服务器列表，用于存储可用的后端服务器
	targets []*Target
	// currentIndex 当前索引，用于轮询负载均衡
	currentIndex int
	// mutex 读写锁，用于保护目标列表的并发访问
	mutex sync.RWMutex
	// reverseProxy HTTP反向代理指针，用于处理HTTP请求转发
	reverseProxy *httputil.ReverseProxy
	// running 运行状态，用于标识代理是否正在运行
	running bool
}

// TCPProxy TCP代理
type TCPProxy struct {
	// config 代理配置指针，用于存储代理配置信息
	config *Config
	// targets 目标服务器列表，用于存储可用的后端服务器
	targets []*Target
	// currentIndex 当前索引，用于轮询负载均衡
	currentIndex int
	// mutex 读写锁，用于保护目标列表的并发访问
	mutex sync.RWMutex
	// running 运行状态，用于标识代理是否正在运行
	running bool
}

// UDPProxy UDP代理
type UDPProxy struct {
	// config 代理配置指针，用于存储代理配置信息
	config *Config
	// targets 目标服务器列表，用于存储可用的后端服务器
	targets []*Target
	// currentIndex 当前索引，用于轮询负载均衡
	currentIndex int
	// mutex 读写锁，用于保护目标列表的并发访问
	mutex sync.RWMutex
	// running 运行状态，用于标识代理是否正在运行
	running bool
}

// GRPCProxy gRPC代理
type GRPCProxy struct {
	// config 代理配置指针，用于存储代理配置信息
	config *Config
	// targets 目标服务器列表，用于存储可用的后端服务器
	targets []*Target
	// currentIndex 当前索引，用于轮询负载均衡
	currentIndex int
	// mutex 读写锁，用于保护目标列表的并发访问
	mutex sync.RWMutex
	// connections gRPC连接池，用于复用gRPC连接
	connections map[string]*grpc.ClientConn
	// running 运行状态，用于标识代理是否正在运行
	running bool
}

// NewHTTPProxy 创建HTTP代理
func NewHTTPProxy(config *Config) (*HTTPProxy, error) {
	if config == nil || len(config.Targets) == 0 {
		return nil, errors.ErrProxyConfigInvalid
	}

	// 设置默认值
	if config.LoadBalanceStrategy == "" {
		config.LoadBalanceStrategy = STRATEGY_ROUND_ROBIN
	}

	proxy := &HTTPProxy{
		config:  config,
		targets: make([]*Target, len(config.Targets)),
	}

	// 复制目标列表
	copy(proxy.targets, config.Targets)

	// 初始化所有目标为健康状态
	for _, target := range proxy.targets {
		target.Healthy = true
	}

	// 创建反向代理
	proxy.reverseProxy = &httputil.ReverseProxy{
		Director: proxy.director,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		ErrorHandler: proxy.errorHandler,
	}

	// 配置TLS
	if config.TLSConfig != nil {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: config.TLSConfig.InsecureSkipVerify,
		}
		proxy.reverseProxy.Transport.(*http.Transport).TLSClientConfig = tlsConfig
	}

	return proxy, nil
}

// director 请求导向器
func (p *HTTPProxy) director(req *http.Request) {
	target := p.selectTarget()
	if target == nil {
		logger.Error("No healthy target available")
		return
	}

	targetURL, err := url.Parse(target.URL)
	if err != nil {
		logger.Errorf("Invalid target URL: %s, error: %v", target.URL, err)
		return
	}

	req.URL.Scheme = targetURL.Scheme
	req.URL.Host = targetURL.Host
	req.URL.Path = targetURL.Path + req.URL.Path
	req.Host = targetURL.Host

	// 添加代理头部
	req.Header.Set("X-Forwarded-For", req.RemoteAddr)
	req.Header.Set("X-Forwarded-Proto", req.URL.Scheme)
	req.Header.Set("X-Forwarded-Host", req.Host)

	logger.Debugf("Proxying request to %s", target.URL)
}

// errorHandler 错误处理器
func (p *HTTPProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	logger.Errorf("Proxy error: %v", err)
	w.WriteHeader(http.StatusBadGateway)
	w.Write([]byte("Bad Gateway"))
}

// selectTarget 选择目标服务器
func (p *HTTPProxy) selectTarget() *Target {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	healthyTargets := make([]*Target, 0)
	for _, target := range p.targets {
		if target.Healthy {
			healthyTargets = append(healthyTargets, target)
		}
	}

	if len(healthyTargets) == 0 {
		return nil
	}

	switch p.config.LoadBalanceStrategy {
	case STRATEGY_ROUND_ROBIN:
		target := healthyTargets[p.currentIndex%len(healthyTargets)]
		p.currentIndex++
		return target
	case STRATEGY_LEAST_CONN:
		var selectedTarget *Target
		minConnections := int64(^uint64(0) >> 1) // 最大int64值
		for _, target := range healthyTargets {
			if target.Connections < minConnections {
				minConnections = target.Connections
				selectedTarget = target
			}
		}
		return selectedTarget
	default:
		return healthyTargets[0]
	}
}

// ServeHTTP 处理HTTP请求
func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.reverseProxy.ServeHTTP(w, r)
}

// Start 启动HTTP代理
func (p *HTTPProxy) Start() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.running {
		return fmt.Errorf("proxy already running")
	}

	// 启动健康检查
	if p.config.HealthCheck != nil && p.config.HealthCheck.Enabled {
		go p.startHealthCheck()
	}

	p.running = true
	logger.Infof("HTTP proxy %s started with %d targets", p.config.Name, len(p.targets))
	return nil
}

// Stop 停止HTTP代理
func (p *HTTPProxy) Stop() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.running = false
	logger.Infof("HTTP proxy %s stopped", p.config.Name)
	return nil
}

// GetConfig 获取配置
func (p *HTTPProxy) GetConfig() *Config {
	return p.config
}

// GetTargets 获取目标列表
func (p *HTTPProxy) GetTargets() []*Target {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.targets
}

// AddTarget 添加目标
func (p *HTTPProxy) AddTarget(target *Target) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	target.Healthy = true
	p.targets = append(p.targets, target)
	logger.Infof("Added target %s to proxy %s", target.URL, p.config.Name)
	return nil
}

// RemoveTarget 移除目标
func (p *HTTPProxy) RemoveTarget(url string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for i, target := range p.targets {
		if target.URL == url {
			p.targets = append(p.targets[:i], p.targets[i+1:]...)
			logger.Infof("Removed target %s from proxy %s", url, p.config.Name)
			return nil
		}
	}

	return fmt.Errorf("target %s not found", url)
}

// startHealthCheck 启动健康检查
func (p *HTTPProxy) startHealthCheck() {
	ticker := time.NewTicker(p.config.HealthCheck.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !p.running {
				return
			}
			p.checkTargetsHealth()
		}
	}
}

// checkTargetsHealth 检查目标健康状态
func (p *HTTPProxy) checkTargetsHealth() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, target := range p.targets {
		go func(t *Target) {
			healthy := p.checkTargetHealth(t)
			if t.Healthy != healthy {
				t.Healthy = healthy
				if healthy {
					logger.Infof("Target %s is now healthy", t.URL)
				} else {
					logger.Warnf("Target %s is now unhealthy", t.URL)
				}
			}
			t.LastCheck = time.Now()
		}(target)
	}
}

// checkTargetHealth 检查单个目标健康状态
func (p *HTTPProxy) checkTargetHealth(target *Target) bool {
	client := &http.Client{
		Timeout: p.config.HealthCheck.Timeout,
	}

	checkURL := target.URL
	if p.config.HealthCheck.Path != "" {
		checkURL = strings.TrimSuffix(target.URL, "/") + p.config.HealthCheck.Path
	}

	resp, err := client.Get(checkURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	expectedStatus := p.config.HealthCheck.ExpectedStatus
	if expectedStatus == 0 {
		expectedStatus = http.StatusOK
	}

	return resp.StatusCode == expectedStatus
}

// NewTCPProxy 创建TCP代理
func NewTCPProxy(config *Config) (*TCPProxy, error) {
	if config == nil || len(config.Targets) == 0 {
		return nil, errors.ErrProxyConfigInvalid
	}

	proxy := &TCPProxy{
		config:  config,
		targets: make([]*Target, len(config.Targets)),
	}

	copy(proxy.targets, config.Targets)

	// 初始化所有目标为健康状态
	for _, target := range proxy.targets {
		target.Healthy = true
	}

	return proxy, nil
}

// HandleConnection 处理TCP连接
func (p *TCPProxy) HandleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	target := p.selectTarget()
	if target == nil {
		logger.Error("No healthy target available for TCP proxy")
		return
	}

	// 连接到目标服务器
	targetConn, err := net.DialTimeout("tcp", target.URL, 30*time.Second)
	if err != nil {
		logger.Errorf("Failed to connect to target %s: %v", target.URL, err)
		return
	}
	defer targetConn.Close()

	logger.Debugf("TCP proxy connection established: %s -> %s", clientConn.RemoteAddr(), target.URL)

	// 双向数据转发
	go func() {
		io.Copy(targetConn, clientConn)
		targetConn.Close()
	}()

	io.Copy(clientConn, targetConn)
}

// selectTarget TCP代理选择目标
func (p *TCPProxy) selectTarget() *Target {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	healthyTargets := make([]*Target, 0)
	for _, target := range p.targets {
		if target.Healthy {
			healthyTargets = append(healthyTargets, target)
		}
	}

	if len(healthyTargets) == 0 {
		return nil
	}

	target := healthyTargets[p.currentIndex%len(healthyTargets)]
	p.currentIndex++
	return target
}

// Start 启动TCP代理
func (p *TCPProxy) Start() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.running = true
	logger.Infof("TCP proxy %s started with %d targets", p.config.Name, len(p.targets))
	return nil
}

// Stop 停止TCP代理
func (p *TCPProxy) Stop() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.running = false
	logger.Infof("TCP proxy %s stopped", p.config.Name)
	return nil
}

// GetConfig 获取TCP代理配置
func (p *TCPProxy) GetConfig() *Config {
	return p.config
}

// GetTargets 获取TCP代理目标列表
func (p *TCPProxy) GetTargets() []*Target {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.targets
}

// AddTarget 添加TCP代理目标
func (p *TCPProxy) AddTarget(target *Target) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	target.Healthy = true
	p.targets = append(p.targets, target)
	return nil
}

// RemoveTarget 移除TCP代理目标
func (p *TCPProxy) RemoveTarget(url string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for i, target := range p.targets {
		if target.URL == url {
			p.targets = append(p.targets[:i], p.targets[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("target %s not found", url)
}

// CreateGinHandler 创建Gin处理器
func (p *HTTPProxy) CreateGinHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		p.ServeHTTP(c.Writer, c.Request)
	}
}

// NewProxy 根据类型创建代理
func NewProxy(config *Config) (Proxy, error) {
	switch config.Type {
	case PROXY_TYPE_HTTP, PROXY_TYPE_HTTPS:
		return NewHTTPProxy(config)
	case PROXY_TYPE_TCP:
		return NewTCPProxy(config)
	default:
		return nil, fmt.Errorf("%w: unsupported proxy type: %s", errors.ErrProxyProtocolNotSupported, config.Type)
	}
}
